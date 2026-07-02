#! /usr/bin/env node

import fs from "fs";
import path from "path";
import process from "process";
import puppeteer from "puppeteer";
import { RequestExplorer } from "./input_sifter2.js";

const SOURCE_BASE = "http://172.28.8.69:8080/";
const TARGET_BASE = "http://127.0.0.1/";


function stripCdata(text) {
    if (typeof text !== "string") {
        return "";
    }
    const trimmed = text.trim();
    const match = trimmed.match(/^<!\[CDATA\[([\s\S]*?)\]\]>$/);
    return match ? match[1] : trimmed;
}


function decodeXmlEntities(text) {
    return String(text || "")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, "\"")
        .replace(/&apos;/g, "'")
        .replace(/&amp;/g, "&");
}


function extractTag(itemXml, tagName) {
    const re = new RegExp(`<${tagName}\\b([^>]*)>([\\s\\S]*?)<\\/${tagName}>`, "i");
    const match = itemXml.match(re);
    if (!match) {
        return { attrs: "", value: "" };
    }
    return {
        attrs: match[1] || "",
        value: decodeXmlEntities(stripCdata(match[2] || "")),
    };
}


function ensureTrailingSlash(urlText) {
    const parsed = new URL(rewriteKnownBase(String(urlText || "")));
    if (!parsed.pathname.endsWith("/")) {
        parsed.pathname = parsed.pathname + "/";
    }
    return parsed.href;
}


function rewriteKnownBase(urlText) {
    let text = String(urlText || "").trim();
    if (!text) {
        return text;
    }
    if (text.startsWith(SOURCE_BASE)) {
        text = TARGET_BASE + text.slice(SOURCE_BASE.length);
    }
    try {
        const parsed = new URL(text);
        if (parsed.protocol === "http:" && parsed.hostname === "127.0.0.1" && parsed.port === "8080") {
            parsed.port = "";
        }
        return parsed.href;
    } catch (ex) {
        return text.replace(SOURCE_BASE, TARGET_BASE);
    }
}


function selectBaseSite(config, parsedRequests) {
    try {
        if (config && typeof config.base_url === "string" && config.base_url.trim().length > 0) {
            return ensureTrailingSlash(config.base_url.trim());
        }
    } catch (ex) {
    }

    try {
        const crawlerCfg = config && typeof config === "object" ? config.request_crawler : null;
        if (crawlerCfg && typeof crawlerCfg.form_url === "string" && crawlerCfg.form_url.trim().length > 0) {
            const loginUrl = new URL(crawlerCfg.form_url.trim());
            return ensureTrailingSlash(loginUrl.origin + "/");
        }
    } catch (ex) {
    }

    if (parsedRequests.length > 0) {
        try {
            const firstUrl = new URL(parsedRequests[0].url);
            return ensureTrailingSlash(firstUrl.origin + "/");
        } catch (ex) {
        }
    }

    throw new Error("无法从 witcher_config.json 或 XML 请求中推断 base_url");
}


function loadConfig(inputDir) {
    const configPath = path.join(inputDir, "witcher_config.json");
    if (!fs.existsSync(configPath)) {
        throw new Error(`缺少配置文件: ${configPath}`);
    }
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
}


function findXmlFiles(inputDir) {
    return fs.readdirSync(inputDir, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".xml"))
        .map((entry) => path.join(inputDir, entry.name))
        .sort((a, b) => a.localeCompare(b));
}


function parseRawHttpRequest(rawText, fallbackUrlText, baseSiteHref) {
    const raw = String(rawText || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const splitIndex = raw.indexOf("\n\n");
    const head = splitIndex >= 0 ? raw.slice(0, splitIndex) : raw;
    const body = splitIndex >= 0 ? raw.slice(splitIndex + 2) : "";
    const lines = head.split("\n");
    const requestLine = (lines.shift() || "").trim();
    const lineMatch = requestLine.match(/^([A-Z]+)\s+(\S+)(?:\s+HTTP\/[0-9.]+)?$/i);
    if (!lineMatch) {
        throw new Error(`无法解析 HTTP 请求首行: ${requestLine}`);
    }

    const method = String(lineMatch[1] || "GET").toUpperCase();
    const target = String(lineMatch[2] || "");
    const headers = {};
    for (const line of lines) {
        const idx = line.indexOf(":");
        if (idx <= 0) {
            continue;
        }
        const key = line.slice(0, idx).trim().toLowerCase();
        const value = line.slice(idx + 1).trim();
        if (key.length === 0) {
            continue;
        }
        if (key === "referer" || key === "origin") {
            headers[key] = rewriteKnownBase(value);
        } else if (key === "host") {
            headers[key] = String(value || "").replace(/^172\.28\.8\.69:8080$/i, "127.0.0.1");
        } else {
            headers[key] = value;
        }
    }

    let absoluteUrl = "";
    try {
        if (/^https?:\/\//i.test(target)) {
            absoluteUrl = rewriteKnownBase(target);
        } else if (fallbackUrlText) {
            absoluteUrl = rewriteKnownBase(new URL(target, rewriteKnownBase(fallbackUrlText)).href);
        } else if (headers.host) {
            absoluteUrl = rewriteKnownBase(new URL(`http://${headers.host}${target}`).href);
        } else {
            absoluteUrl = rewriteKnownBase(new URL(target, rewriteKnownBase(baseSiteHref)).href);
        }
    } catch (ex) {
        absoluteUrl = rewriteKnownBase(fallbackUrlText ? String(fallbackUrlText) : new URL(target, baseSiteHref).href);
    }

    const baseSite = new URL(rewriteKnownBase(baseSiteHref));
    const normalizedUrl = new URL(absoluteUrl);
    if (normalizedUrl.origin !== baseSite.origin) {
        normalizedUrl.protocol = baseSite.protocol;
        normalizedUrl.host = baseSite.host;
    }

    if (headers.host) {
        headers.host = normalizedUrl.host;
    }

    return {
        url: normalizedUrl.href,
        method,
        headers,
        postData: body,
    };
}


function parseBurpXmlFile(filePath, baseSiteHref) {
    const xmlText = fs.readFileSync(filePath, "utf8").replace(/\u0000/g, "");
    const itemMatches = xmlText.match(/<item\b[\s\S]*?<\/item>/gi) || [];
    const parsedRequests = [];

    for (const itemXml of itemMatches) {
        const requestTag = extractTag(itemXml, "request");
        if (!requestTag.value) {
            continue;
        }
        const urlTag = extractTag(itemXml, "url");
        const methodTag = extractTag(itemXml, "method");
        const statusTag = extractTag(itemXml, "status");
        const requestIsBase64 = /base64\s*=\s*"true"/i.test(requestTag.attrs || "");

        let decodedRequest = requestTag.value;
        if (requestIsBase64) {
            decodedRequest = Buffer.from(requestTag.value, "base64").toString("latin1");
        }

        const parsed = parseRawHttpRequest(decodedRequest, urlTag.value, baseSiteHref);
        if (!parsed.method && methodTag.value) {
            parsed.method = methodTag.value.trim().toUpperCase();
        }
        parsed.sourceFile = path.basename(filePath);
        parsed.response_status = parseInt(statusTag.value || "0", 10) || 0;
        parsedRequests.push(parsed);
    }

    return parsedRequests;
}


function buildRequestKey(requestInfo) {
    return `${requestInfo.method} ${requestInfo.url} ${requestInfo.postData || ""}`;
}


function addInputValue(inputSet, key, value) {
    const normalizedKey = String(key || "").trim();
    if (!normalizedKey) {
        return;
    }
    const normalizedValue = value === undefined || value === null ? "" : String(value);
    inputSet.add(`${normalizedKey}=${normalizedValue}`);
}


function collectInputSet(inputSet, requestInfo) {
    try {
        const parsedUrl = new URL(requestInfo.url);
        for (const [key, value] of parsedUrl.searchParams.entries()) {
            addInputValue(inputSet, key, value);
        }
    } catch (ex) {
    }

    const cookieHeader = requestInfo.headers.cookie || requestInfo.headers.Cookie || "";
    for (const cookiePair of String(cookieHeader || "").split(";")) {
        const trimmed = cookiePair.trim();
        if (!trimmed || trimmed.indexOf("=") === -1) {
            continue;
        }
        const idx = trimmed.indexOf("=");
        addInputValue(inputSet, trimmed.slice(0, idx), trimmed.slice(idx + 1));
    }

    const contentType = String(requestInfo.headers["content-type"] || requestInfo.headers["Content-Type"] || "");
    if (requestInfo.postData && contentType.indexOf("application/x-www-form-urlencoded") > -1) {
        const params = new URLSearchParams(requestInfo.postData);
        for (const [key, value] of params.entries()) {
            addInputValue(inputSet, key, value);
        }
        return;
    }

    if (requestInfo.postData && contentType.indexOf("application/json") > -1) {
        try {
            const parsed = JSON.parse(requestInfo.postData);
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
                for (const [key, value] of Object.entries(parsed)) {
                    if (value === null || value === undefined) {
                        addInputValue(inputSet, key, "");
                    } else if (typeof value !== "object") {
                        addInputValue(inputSet, key, value);
                    }
                }
            }
        } catch (ex) {
        }
    }
}


function makeStoredRequest(requestInfo, requestKey, index) {
    const headers = Object.assign({}, requestInfo.headers);
    return {
        _id: index + 1,
        _urlstr: requestInfo.url,
        _url: requestInfo.url,
        _resourceType: "document",
        _method: requestInfo.method,
        _postData: requestInfo.postData || "",
        _headers: headers,
        attempts: 0,
        processed: 0,
        from: `XMLReplay:${requestInfo.sourceFile}`,
        _cookieData: headers.cookie || headers.Cookie || "",
        key: requestKey,
        response_status: requestInfo.response_status || 0,
    };
}


function writeRequestData(inputDir, storedRequests, inputSet) {
    const payload = {
        requestsFound: storedRequests,
        seedRequestsFound: {},
        inputSet: Array.from(inputSet),
        _witcher_meta: {
            init: {
                xml_driver: true,
                xml_mode: "passthrough",
            },
        },
    };
    const outputPath = path.join(inputDir, "request_data.json");
    fs.writeFileSync(outputPath, JSON.stringify(payload, null, 2));
    return outputPath;
}


function createLoginExplorer(inputDir, baseSiteHref, headless) {
    const helperAppData = {
        requestsFound: {},
        seedRequestsFound: {},
        site_url: new URL(baseSiteHref),
        headless,
        currentURLRound: 1,
        setIgnoreValues() {
        },
        setUrlUniqueIfValueUnique() {
        },
        addRequest(foundRequest) {
            const requestKey = foundRequest.getRequestKey();
            this.requestsFound[requestKey] = foundRequest;
            return true;
        },
        addInterestingRequest() {
            return 0;
        },
        numRequestsFound() {
            return 0;
        },
        numInputsFound() {
            return 0;
        },
    };
    return new RequestExplorer(helperAppData, 0, inputDir, null);
}


async function launchXmlBrowser(headless) {
    try {
        return await puppeteer.launch({
            headless,
            args: [
                "--disable-features=site-per-process",
                "--window-size=1600,900",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
            defaultViewport: null,
        });
    } catch (xerror) {
        if (xerror && typeof xerror.message === "string" && xerror.message.indexOf("Unable to open X display") > -1) {
            return await puppeteer.launch({
                headless,
                args: [
                    "--disable-features=site-per-process",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            });
        }
        throw xerror;
    }
}


async function maybeLogin(browser, inputDir, baseSiteHref, headless) {
    try {
        const openPages = await browser.pages();
        for (const openPage of openPages) {
            try {
                await openPage.close({ runBeforeUnload: false });
            } catch (ex) {
            }
        }
    } catch (ex) {
    }
    const explorer = createLoginExplorer(inputDir, baseSiteHref, headless);
    if (!explorer.loginData || !("form_url" in explorer.loginData)) {
        return explorer.loginData || null;
    }
    if (!explorer.hasCompleteLoginSelectors()) {
        console.log("[WC] XML driver skip login: missing usernameSelector/passwordSelector");
        return explorer.loginData || null;
    }
    if (!explorer.hasValidLoginFormUrl()) {
        console.log("[WC] XML driver skip login: invalid form_url");
        return explorer.loginData || null;
    }
    const loginPage = await browser.newPage();
    try {
        await explorer.do_login(loginPage, { noProcessExit: true });
    } finally {
        try {
            await loginPage.close();
        } catch (ex) {
        }
    }
    return explorer.loginData || null;
}


async function buildCookieHeaderForUrl(page, requestInfo) {
    const liveCookies = await page.cookies(requestInfo.url);
    if (liveCookies && liveCookies.length > 0) {
        return liveCookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
    }
    return requestInfo.headers.cookie || requestInfo.headers.Cookie || "";
}


function isConfiguredLoginPageUrl(urlText, loginData) {
    try {
        const currentUrl = new URL(String(urlText || ""));
        if (loginData && typeof loginData.form_url === "string" && loginData.form_url.trim()) {
            const loginUrl = new URL(rewriteKnownBase(loginData.form_url.trim()));
            const currentPath = String(currentUrl.pathname || "").replace(/\/+$/, "") || "/";
            const loginPath = String(loginUrl.pathname || "").replace(/\/+$/, "") || "/";
            return currentUrl.origin === loginUrl.origin && currentPath === loginPath;
        }
        return false;
    } catch (ex) {
        return false;
    }
}


async function replayOnce(browser, requestInfo) {
    const page = await browser.newPage();
    let responseStatus = requestInfo.response_status || 0;
    let finalUrl = requestInfo.url;
    let redirectedToLogin = false;
    let mainResponseSeen = false;
    let mainResponseUrl = requestInfo.url;
    let resolveMainResponse = null;
    const mainResponsePromise = new Promise((resolve) => {
        resolveMainResponse = resolve;
    });
    try {
        await page.setCacheEnabled(false);
        await page.setDefaultNavigationTimeout(45000);
        await page.setRequestInterception(true);

        const targetHref = requestInfo.url;
        let mainRequestSeen = false;

        page.on("request", async (req) => {
            try {
                if (!mainRequestSeen && req.isNavigationRequest() && req.frame() === page.mainFrame()) {
                    mainRequestSeen = true;
                    const liveCookieHeader = await buildCookieHeaderForUrl(page, requestInfo);
                    const replayHeaders = {};
                    for (const [headerName, headerValue] of Object.entries(requestInfo.headers || {})) {
                        const lowerName = String(headerName || "").toLowerCase();
                        if (!lowerName || lowerName === "host" || lowerName === "content-length" || lowerName === "cookie") {
                            continue;
                        }
                        replayHeaders[lowerName] = headerValue;
                    }
                    if (liveCookieHeader) {
                        replayHeaders.cookie = liveCookieHeader;
                    }
                    const overrides = {
                        method: requestInfo.method,
                        headers: replayHeaders,
                    };
                    if (requestInfo.postData && requestInfo.method !== "GET" && requestInfo.method !== "HEAD") {
                        overrides.postData = requestInfo.postData;
                    }
                    await req.continue(overrides);
                    return;
                }
                await req.continue();
            } catch (ex) {
                try {
                    await req.continue();
                } catch (inner) {
                }
            }
        });
        page.on("response", async (resp) => {
            try {
                const req = resp.request ? resp.request() : null;
                if (!req) {
                    return;
                }
                if (req.isNavigationRequest && req.isNavigationRequest() && req.frame() === page.mainFrame()) {
                    mainResponseSeen = true;
                    mainResponseUrl = resp.url ? resp.url() : mainResponseUrl;
                    if (typeof resp.status === "function") {
                        responseStatus = resp.status();
                    }
                    if (resolveMainResponse) {
                        resolveMainResponse({
                            status: responseStatus,
                            url: mainResponseUrl,
                        });
                        resolveMainResponse = null;
                    }
                }
            } catch (ex) {
            }
        });

        try {
            const gotoPromise = page.goto(targetHref, {
                waitUntil: "domcontentloaded",
                timeout: 45000,
            });
            let acceptedAfterMainResponse = false;
            const guardedGotoPromise = gotoPromise
                .then((response) => {
                    if (response && typeof response.status === "function") {
                        responseStatus = response.status();
                    }
                    return response;
                });
            const raced = await Promise.race([
                guardedGotoPromise.then((response) => ({
                    kind: "goto",
                    response,
                })),
                mainResponsePromise.then((info) => ({
                    kind: "main_response",
                    info,
                })),
            ]);
            if (raced && raced.kind === "main_response") {
                acceptedAfterMainResponse = true;
                finalUrl = (raced.info && raced.info.url) ? raced.info.url : finalUrl;
                guardedGotoPromise.catch((ex) => {
                    const msg = String(ex && ex.message ? ex.message : ex);
                    const ignorable = (
                        (ex && ex.name === "TimeoutError") ||
                        msg.includes("Navigation timeout") ||
                        msg.includes("browser has disconnected") ||
                        msg.includes("Target closed") ||
                        msg.includes("Session closed")
                    );
                    if (!ignorable) {
                        console.log(`[WC] XML replay post-response navigation issue ignored: ${requestInfo.method} ${requestInfo.url} ${ex && ex.message ? ex.message : ex}`);
                    }
                });
                console.log(`[WC] XML replay accepted after main response: ${requestInfo.method} ${requestInfo.url} status=${responseStatus}`);
                return {
                    responseStatus,
                    finalUrl,
                    redirectedToLogin,
                };
            } else if (raced && raced.response && typeof raced.response.status === "function") {
                responseStatus = raced.response.status();
            }
        } catch (ex) {
            const isTimeout = !!(ex && (ex.name === "TimeoutError" || String(ex.message || ex).includes("Navigation timeout")));
            if (!isTimeout || !mainResponseSeen) {
                throw ex;
            }
            console.log(`[WC] XML replay timeout accepted after main response: ${requestInfo.method} ${requestInfo.url} status=${responseStatus}`);
            finalUrl = mainResponseUrl || finalUrl;
            return {
                responseStatus,
                finalUrl,
                redirectedToLogin,
            };
        }
        try {
            finalUrl = await page.url();
        } catch (ex) {
            finalUrl = mainResponseUrl || finalUrl;
        }
    } finally {
        try {
            await page.close();
        } catch (ex) {
        }
    }
    return {
        responseStatus,
        finalUrl,
        redirectedToLogin,
    };
}


async function replayExactRequest(browser, requestInfo, inputDir, baseSiteHref, headless, loginData) {
    let replayResult = await replayOnce(browser, requestInfo);
    let loginDetected = isConfiguredLoginPageUrl(replayResult.finalUrl, loginData);
    if (!loginDetected) {
        return replayResult.responseStatus;
    }

    console.log(`[WC] XML replay detected login page for ${requestInfo.method} ${requestInfo.url}, relogin once`);
    try {
        await maybeLogin(browser, inputDir, baseSiteHref, headless);
    } catch (ex) {
        console.log("[WC] XML replay relogin failed, skip current request");
        try {
            console.log(ex && ex.stack ? ex.stack : ex);
        } catch (inner) {
        }
        return replayResult.responseStatus;
    }

    replayResult = await replayOnce(browser, requestInfo);
    loginDetected = isConfiguredLoginPageUrl(replayResult.finalUrl, loginData);
    if (loginDetected) {
        console.log(`[WC] XML replay still lands on login page after relogin, skip request ${requestInfo.method} ${requestInfo.url}`);
    }
    return replayResult.responseStatus;
}


async function buildRequestDataFromXmlDir(inputDir, headless = true) {
    const config = loadConfig(inputDir);
    const xmlFiles = findXmlFiles(inputDir);
    if (xmlFiles.length === 0) {
        throw new Error(`目录下没有找到 XML 文件: ${inputDir}`);
    }

    let parsedRequests = [];
    const baseHint = selectBaseSite(config, []);
    for (const xmlFile of xmlFiles) {
        parsedRequests = parsedRequests.concat(parseBurpXmlFile(xmlFile, baseHint));
    }
    if (parsedRequests.length === 0) {
        throw new Error(`未从 XML 中解析到任何请求: ${inputDir}`);
    }

    const baseSiteHref = selectBaseSite(config, parsedRequests);
    const inputSet = new Set();
    const storedRequests = {};
    const browser = await launchXmlBrowser(headless);
    let loginData = null;
    try {
        loginData = await maybeLogin(browser, inputDir, baseSiteHref, headless);
        for (let index = 0; index < parsedRequests.length; index++) {
            const requestInfo = parsedRequests[index];
            console.log(`[WC] XML replay ${index + 1}/${parsedRequests.length} ${requestInfo.method} ${requestInfo.url}`);
            try {
                requestInfo.response_status = await replayExactRequest(browser, requestInfo, inputDir, baseSiteHref, headless, loginData);
            } catch (ex) {
                console.log("[WC] XML replay failed, continue next request");
                try {
                    console.log(ex && ex.stack ? ex.stack : ex);
                } catch (inner) {
                }
            }
            collectInputSet(inputSet, requestInfo);
            const requestKey = buildRequestKey(requestInfo);
            storedRequests[requestKey] = makeStoredRequest(requestInfo, requestKey, index);
        }
    } finally {
        try {
            await browser.close();
        } catch (ex) {
        }
    }

    const outputFile = writeRequestData(inputDir, storedRequests, inputSet);
    return {
        outputFile,
        xmlCount: xmlFiles.length,
        requestCount: Object.keys(storedRequests).length,
        inputCount: inputSet.size,
    };
}


function parseArgs(argv) {
    const args = {
        inputDir: "",
        headless: true,
    };

    for (let i = 0; i < argv.length; i++) {
        const token = String(argv[i] || "");
        if (token === "--show-browser") {
            args.headless = false;
            continue;
        }
        if (!args.inputDir) {
            args.inputDir = token;
        }
    }

    if (!args.inputDir) {
        throw new Error("用法: node xml_request_data_driver.js <输入目录> [--show-browser]");
    }

    args.inputDir = path.resolve(args.inputDir);
    return args;
}


async function main(argv) {
    const args = parseArgs(argv);
    const result = await buildRequestDataFromXmlDir(args.inputDir, args.headless);
    console.log(`[WC] XML files=${result.xmlCount} requests=${result.requestCount} inputs=${result.inputCount}`);
    console.log(`[WC] request_data written to ${result.outputFile}`);
    return 0;
}


main(process.argv.slice(2))
    .then((code) => {
        process.exit(code);
    })
    .catch((err) => {
        console.error(err && err.stack ? err.stack : err);
        process.exit(1);
    });
