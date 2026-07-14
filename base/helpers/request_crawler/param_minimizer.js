#! /usr/bin/env node

import fs from "fs";
import path from "path";
import process from "process";
import puppeteer from "puppeteer";

import {AppData, RequestExplorer} from "./input_sifter2.js";
import {FoundRequest} from "./FoundRequest.js";

function parseArgs(argv){
    let args = argv.slice(2);
    let headless = true;
    let acceptFullParamsWithoutMinimization = false;
    let fullParamsOutput = "";
    args = args.filter((a) => {
        if (a === "--no-headless"){
            headless = false;
            return false;
        }
        if (a === "--accept-full-params-without-minimization"){
            acceptFullParamsWithoutMinimization = true;
            return false;
        }
        return true;
    });
    let nextArgs = [];
    for (let i = 0; i < args.length; i++){
        if (args[i] === "--full-params-output"){
            if (i + 1 < args.length){
                fullParamsOutput = args[i + 1];
                i += 1;
            }
            continue;
        }
        nextArgs.push(args[i]);
    }
    args = nextArgs;
    if (args.length > 0 && (args[0] === "request_crawler" || args[0] === "request-crawler")){
        args = args.slice(1);
    }
    if (args.length < 4){
        console.log("Usage:\n\tnode param_minimizer.js [request_crawler] BASE_SITE BASE_APPDIR URLS_TXT PARAMS_JSON [--no-headless] [--accept-full-params-without-minimization] [--full-params-output PATH]\n");
        process.exit(2);
    }
    return {
        baseSite: args[0],
        baseAppdir: args[1],
        urlsTxt: args[2],
        paramsJson: args[3],
        headless,
        acceptFullParamsWithoutMinimization,
        fullParamsOutput,
    };
}

function loadLines(fn){
    if (!fs.existsSync(fn)){
        return [];
    }
    return fs.readFileSync(fn, "utf8").split(/\r?\n/).map(s => s.trim()).filter(s => s.length > 0);
}

function loadParams(fn){
    if (!fs.existsSync(fn)){
        return {GET:{}, POST:{}, COOKIE:{}};
    }
    let obj = JSON.parse(fs.readFileSync(fn, "utf8"));
    return {
        GET: obj.GET || {},
        POST: obj.POST || {},
        COOKIE: obj.COOKIE || {},
    };
}

function pickFirstValues(map){
    let out = {};
    for (let k of Object.keys(map)){
        let vals = map[k];
        if (Array.isArray(vals) && vals.length > 0){
            out[k] = vals[0];
        } else if (typeof vals === "string"){
            out[k] = vals;
        }
    }
    return out;
}

function buildQuery(params){
    let parts = [];
    for (let k of Object.keys(params)){
        let v = params[k];
        parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
    return parts.join("&");
}

function buildPostBody(params){
    return buildQuery(params);
}

function buildCookieString(params){
    let parts = [];
    for (let k of Object.keys(params)){
        let v = params[k];
        parts.push(`${k}=${v}`);
    }
    return parts.join("; ");
}

async function cookiesToHeader(page, baseSite){
    try{
        let cookies = await page.cookies(baseSite);
        let parts = [];
        for (let c of cookies){
            parts.push(`${c.name}=${c.value}`);
        }
        return parts.join("; ");
    } catch(ex){
        return "";
    }
}

function mergeCookieHeaders(baseCookie, extraCookie){
    let b = (baseCookie || "").trim();
    let e = (extraCookie || "").trim();
    if (b.length === 0){
        return e;
    }
    if (e.length === 0){
        return b;
    }
    return `${b}; ${e}`;
}

function buildUrlWithGet(baseUrl, getParams){
    let u = new URL(baseUrl);
    for (let k of Object.keys(getParams)){
        u.searchParams.set(k, getParams[k]);
    }
    return u.href;
}

const FAST_SNIPPET_BYTES = 4096;
const FAST_HEAD_TIMEOUT_MS = 1200;
const FAST_MIN_NORMAL_BODY_BYTES = 320;
const FAST_MIN_5XX_BODY_BYTES = 700;
const FAST_MIN_TEXT_RATIO = 0.18;

function getHtmlQualitySignals(snippet){
    const raw = String(snippet || "");
    const s = raw.toLowerCase();
    const hasDocType = s.includes("<!doctype html");
    const hasHtmlOpen = s.includes("<html");
    const hasHtmlClose = s.includes("</html>");
    const hasHeadOpen = s.includes("<head");
    const hasHeadClose = s.includes("</head>");
    const hasBodyOpen = s.includes("<body");
    const hasBodyClose = s.includes("</body>");
    const structuralMarkers = ["<main", "<form", "<table", "<section", "<article", "<nav", "<header", "<footer", "<div"];
    let structuralCount = 0;
    for (let i = 0; i < structuralMarkers.length; i++){
        if (s.includes(structuralMarkers[i])){
            structuralCount += 1;
        }
    }
    const textOnly = s.replace(/<script[\s\S]*?<\/script>/g, " ")
        .replace(/<style[\s\S]*?<\/style>/g, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    const textRatio = raw.length > 0 ? textOnly.length / raw.length : 0;
    const completeHtml = hasHtmlOpen && hasHtmlClose && hasHeadOpen && hasHeadClose && hasBodyOpen && hasBodyClose;
    const semicompleteHtml = hasHtmlOpen && hasBodyOpen && hasBodyClose && structuralCount >= 2;
    return {
        completeHtml,
        semicompleteHtml,
        structuralCount,
        textLength: textOnly.length,
        textRatio,
        hasDocType,
        hasFrameset: s.includes("<frameset")
    };
}

function hasClearHtmlStructure(snippet){
    const q = getHtmlQualitySignals(snippet);
    if (q.hasFrameset){
        return true;
    }
    if (q.completeHtml){
        return q.structuralCount >= 1 || q.textLength >= 120;
    }
    return q.semicompleteHtml && q.textLength >= 120 && q.textRatio >= FAST_MIN_TEXT_RATIO;
}

function hasValuableErrorPage(snippet){
    const s = String(snippet || "").toLowerCase();
    const markers = [
        "xdebug-error",
        "call stack",
        "warning:",
        "notice:",
        "fatal error",
        "parse error",
        "uncaught",
        "stack trace",
        "traceback",
        "simplexml_load_string",
        "trying to get property",
        "on line <i>",
        "xe-warning",
        "xe-notice",
        "xe-fatal-error"
    ];
    let hits = 0;
    for (let i = 0; i < markers.length; i++){
        if (s.includes(markers[i])){
            hits += 1;
        }
    }
    const hasErrorTable = s.includes("<table") && (s.includes("xdebug-error") || s.includes("call stack"));
    return hits >= 2 || hasErrorTable;
}

function shouldStaticSkipUrl(rawUrl){
    try{
        const u = new URL(rawUrl);
        const pathname = (u.pathname || "").toLowerCase();
        const href = u.href.toLowerCase();
        const ext = (pathname.match(/\.([a-z0-9]+)$/) || [null, ""])[1];
        if (pathname.includes("/3rdparty/") || pathname.includes("/vendor/") || pathname.includes("/node_modules/") || pathname.includes("/tests/") || pathname.includes("/test/")){
            return {skip:true, reason:"thirdparty-or-test"};
        }
        if ((pathname.includes("/src/") || pathname.includes("/lib/")) && pathname.endsWith(".php") && !pathname.endsWith("/index.php")){
            return {skip:true, reason:"source-tree-php"};
        }
        const staticExt = new Set([
            "js","css","map","png","jpg","jpeg","gif","svg","ico","webp","woff","woff2","ttf","eot","otf",
            "pdf","zip","gz","tgz","bz2","7z","rar","tar","mp3","mp4","avi","mov","mkv","webm"
        ]);
        if (staticExt.has(ext)){
            return {skip:true, reason:`static-ext:${ext}`};
        }
        if (/\/(logout|signout|logoff)(\/|$)|[?&](logout|signout|logoff)=/.test(href)){
            return {skip:true, reason:"logout"};
        }
        if (/\/(help|docs|documentation|manual|faq|support)(\/|$)/.test(pathname)){
            return {skip:true, reason:"help"};
        }
        if (/\/(download|exports?|attachment|attachments|file-download|dl)(\/|$)/.test(pathname)){
            return {skip:true, reason:"download-endpoint"};
        }
        const keys = Array.from(u.searchParams.keys()).map(k => k.toLowerCase());
        if (keys.length > 0){
            const langKeys = new Set(["lang","language","locale","i18n","setlang","setlanguage"]);
            if (keys.every(k => langKeys.has(k))){
                return {skip:true, reason:"lang-switch"};
            }
            const pagingKeys = new Set(["page","p","offset","start","limit","per_page","perpage","pagesize","ipp"]);
            if (keys.every(k => pagingKeys.has(k))){
                return {skip:true, reason:"pure-pagination"};
            }
            if (keys.some(k => ["download","export","attachment","file","filename"].includes(k))){
                return {skip:true, reason:"download-query"};
            }
        }
    } catch(ex){
    }
    return {skip:false, reason:"-"};
}

async function ensureLoggedIn(page, appData, baseAppdir){
    let tmpApp = appData;
    tmpApp.requestsFound = {};
    tmpApp.seedRequestsFound = {};
    tmpApp.collectedURL = 0;
    let re = new RequestExplorer(tmpApp, 0, baseAppdir, null);
    if (re.loginData !== undefined && "form_url" in re.loginData){
        try{
            let beforeUrl = "";
            let beforeCookies = [];
            try{ beforeUrl = await page.url(); } catch(ex){}
            try{ beforeCookies = await page.cookies(); } catch(ex){}
            console.log(`[PM-DEBUG] ensureLoggedIn start phase=${page.__phase || "-"} currentUrl=${beforeUrl || "-"} cookieCount=${Array.isArray(beforeCookies) ? beforeCookies.length : 0}`);
            console.log(`[PM-DEBUG] ensureLoggedIn loginConfig form_url=${re.loginData.form_url || "-"} submitType=${re.loginData.submitType || "-"} userSel=${re.loginData.usernameSelector || "-"} passSel=${re.loginData.passwordSelector || "-"} submitSel=${re.loginData.form_submit_selector || "-"}`);
            await re.do_login(page, {attachInterceptor:false, noProcessExit:true});
            let afterUrl = "";
            let afterCookies = [];
            try{ afterUrl = await page.url(); } catch(ex){}
            try{ afterCookies = await page.cookies(); } catch(ex){}
            console.log(`[PM-DEBUG] ensureLoggedIn success phase=${page.__phase || "-"} currentUrl=${afterUrl || "-"} cookieCount=${Array.isArray(afterCookies) ? afterCookies.length : 0}`);
            return {performed:true, ok:true};
        } catch(ex){
            let failUrl = "";
            let failCookies = [];
            try{ failUrl = await page.url(); } catch(ex2){}
            try{ failCookies = await page.cookies(); } catch(ex2){}
            console.log(`[PM-DEBUG] ensureLoggedIn failed phase=${page.__phase || "-"} currentUrl=${failUrl || "-"} cookieCount=${Array.isArray(failCookies) ? failCookies.length : 0}`);
            return {performed:true, ok:false, err: (ex && ex.stack) ? ex.stack : String(ex)};
        }
    }
    return {performed:false, ok:true};
}

function isInteractivePageQuiet(response, responseText){
    try {
        JSON.parse(responseText);
        return false;
    } catch (SyntaxException){
    }
    if (response.headers().hasOwnProperty("content-type")){
        let contentType = response.headers()["content-type"];
        if (contentType === "application/javascript" || contentType === "text/css" || contentType.startsWith("image/") || contentType === "application/json"){
            return false;
        }
    }
    if (hasClearHtmlStructure(responseText) || responseText.search(/<frameset[ >]/) > -1){
        return true;
    }
    return false;
}

function hasValuable5xxSignals(responseText){
    const text = String(responseText || "").slice(0, FAST_SNIPPET_BYTES);
    const lower = text.toLowerCase();
    const businessIndicators = [
        "sql", "mysql", "query", "select", "insert",
        "warning:", "fatal error", "stack trace",
        "line ", "file ", "/var/www",
        "exception", "backtrace", "debug",
        "sqlstate", "pdoexception", "database error", "db error",
        "uncaught", "call stack", "traceback", "stacktrace",
        "undefined index", "undefined variable", "notice:",
        "parse error", "syntax error", "permission denied",
        "not found in", "at line", "on line"
    ];
    let hit = [];
    for (let i = 0; i < businessIndicators.length; i++){
        const kw = businessIndicators[i];
        if (lower.indexOf(kw) > -1){
            hit.push(kw);
        }
    }
    const htmlQuality = getHtmlQualitySignals(text);
    const hasBusiness = hit.length > 0;
    const hasStructuredHtml = htmlQuality.completeHtml && htmlQuality.textLength >= 160;
    const enoughBody = text.trim().length >= FAST_MIN_5XX_BODY_BYTES;
    const ok = enoughBody && hasClearHtmlStructure(text) && (hasBusiness || hasStructuredHtml || hasValuableErrorPage(text));
    return {ok, hitCount: hit.length, enoughBody, hasStructuredHtml, htmlQuality};
}

function createOverrideHandler(getOverride, getPhase){
    return async function(req){
        try{
            const phase = getPhase ? getPhase() : "minimize";
            if (phase !== "minimize"){
                try{ req.continue(); } catch(e){}
                return;
            }
            try{
                if (req.isNavigationRequest() && req.redirectChain && req.redirectChain().length > 0){
                    let isMainFrame = false;
                    try{
                        let fr = req.frame();
                        isMainFrame = fr && fr.parentFrame && fr.parentFrame() === null;
                    } catch(ex){
                        isMainFrame = false;
                    }
                    if (isMainFrame){
                        let status = 0;
                        try{
                            let chain = req.redirectChain();
                            let prevReq = chain[chain.length - 1];
                            let prevResp = prevReq ? prevReq.response() : null;
                            status = prevResp ? prevResp.status() : 0;
                        } catch(ex){
                            status = 0;
                        }
                        if (req && req.frame){
                            try{
                                const fr = req.frame();
                                const pg = fr && fr.page ? fr.page() : null;
                                if (pg){
                                    pg.__lastRedirectAbortInfo = {status};
                                }
                            } catch(ex){
                            }
                        }
                        try{ req.abort(); } catch(e){}
                        return;
                    }
                }
            } catch(ex){
            }
            let ov = getOverride();
            if (!ov){
                try{ req.continue(); } catch(e){}
                return;
            }
            if (ov.method === "POST" && req.isNavigationRequest() && req.frame() === ov.page.mainFrame()){
                let headers = {
                    ...req.headers(),
                    "content-type": "application/x-www-form-urlencoded",
                };
                if (ov.cookieHeader && ov.cookieHeader.length > 0){
                    headers["cookie"] = ov.cookieHeader;
                }
                try{ req.continue({method:"POST", postData: ov.postData, headers}); } catch(e){}
                return;
            }
            if (ov.cookieHeader && ov.cookieHeader.length > 0){
                let headers = {...req.headers(), "cookie": ov.cookieHeader};
                try{ req.continue({headers}); } catch(e){}
                return;
            }
            try{ req.continue(); } catch(e){}
        } catch(ex){
            try{ req.continue(); } catch(e){}
        }
    };
}

function withTimeout(promise, ms){
    let timeoutId = null;
    let timeoutPromise = new Promise((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error("timeout")), ms);
    });
    return Promise.race([promise, timeoutPromise]).finally(() => {
        if (timeoutId){
            clearTimeout(timeoutId);
        }
    });
}

async function waitForPmRelogin(page){
    try{
        if (page && typeof page.__pmWaitWhileRelogin === "function"){
            await page.__pmWaitWhileRelogin();
        }
    } catch(ex){
    }
}

async function fastFetchProbe(page, targetUrl, method, postData="", cookieHeader=""){
    try{
        await waitForPmRelogin(page);
        return await page.evaluate(async ({url, m, timeoutMs, maxBytes, postBody, cookie}) => {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), timeoutMs);
            try{
                const reqHeaders = {};
                if (cookie && String(cookie).trim().length > 0){
                    reqHeaders["cookie"] = String(cookie);
                }
                if (m === "POST"){
                    reqHeaders["content-type"] = "application/x-www-form-urlencoded";
                }
                const resp = await fetch(url, {
                    method: m,
                    redirect: "follow",
                    credentials: "include",
                    cache: "no-store",
                    headers: reqHeaders,
                    body: m === "POST" ? String(postBody || "") : undefined,
                    signal: ctrl.signal
                });
                
                const respHeaders = {};
                resp.headers.forEach((v, k) => { respHeaders[String(k).toLowerCase()] = v; });
                
                let actualStatus = resp.status;
                if (resp.redirected) {
                    actualStatus = 302;
                    respHeaders["location"] = resp.url;
                } else if (actualStatus === 0 && resp.type === "opaqueredirect") {
                    actualStatus = 302;
                }
                let snippet = "";
                if (m !== "HEAD"){
                    try{
                        const txt = await resp.text();
                        snippet = String(txt || "").slice(0, maxBytes);
                    } catch(ex){
                        snippet = "";
                    }
                }
                return {ok:true, status:actualStatus, headers:respHeaders, snippet, finalUrl: resp.url || "", redirected: !!resp.redirected};
            } catch (ex) {
                return {ok:false, status:0, headers:{}, snippet:"", error:String(ex && ex.message ? ex.message : ex)};
            } finally {
                clearTimeout(timer);
            }
        }, {
            url:targetUrl,
            m:method,
            timeoutMs:FAST_HEAD_TIMEOUT_MS,
            maxBytes:FAST_SNIPPET_BYTES,
            postBody:postData || "",
            cookie:cookieHeader || ""
        });
    } catch(ex){
        return {ok:false, status:0, headers:{}, snippet:"", error:String(ex && ex.message ? ex.message : ex)};
    }
}

async function fastStatusProbe(page, targetUrl, method="GET", postData="", cookieHeader=""){
    try{
        await waitForPmRelogin(page);
        return await page.evaluate(async ({url, m, timeoutMs, postBody, cookie}) => {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), timeoutMs);
            try{
                const reqHeaders = {};
                if (cookie && String(cookie).trim().length > 0){
                    reqHeaders["cookie"] = String(cookie);
                }
                if (m === "POST"){
                    reqHeaders["content-type"] = "application/x-www-form-urlencoded";
                }
                const resp = await fetch(url, {
                    method: m,
                    redirect: "follow",
                    credentials: "include",
                    cache: "no-store",
                    headers: reqHeaders,
                    body: m === "POST" ? String(postBody || "") : undefined,
                    signal: ctrl.signal
                });
                const respHeaders = {};
                resp.headers.forEach((v, k) => { respHeaders[String(k).toLowerCase()] = v; });
                let actualStatus = resp.status;
                if (resp.redirected) {
                    actualStatus = 302;
                    respHeaders["location"] = resp.url;
                } else if (actualStatus === 0 && resp.type === "opaqueredirect") {
                    actualStatus = 302;
                }
                return {ok:true, status:actualStatus, headers:respHeaders, finalUrl: resp.url || "", redirected: !!resp.redirected};
            } catch (ex) {
                return {ok:false, status:0, headers:{}, error:String(ex && ex.message ? ex.message : ex), finalUrl:"", redirected:false};
            } finally {
                clearTimeout(timer);
            }
        }, {
            url:targetUrl,
            m:method,
            timeoutMs:FAST_HEAD_TIMEOUT_MS,
            postBody:postData || "",
            cookie:cookieHeader || ""
        });
    } catch(ex){
        return {ok:false, status:0, headers:{}, error:String(ex && ex.message ? ex.message : ex), finalUrl:"", redirected:false};
    }
}

async function quickPrecheck(page, targetUrl, method="GET", postData="", cookieHeader="", baseUrl=""){
    const urlToStaticallyCheck = baseUrl || targetUrl;
    const staticSkip = shouldStaticSkipUrl(urlToStaticallyCheck);
    if (staticSkip.skip){
        return {skip:true, reason:staticSkip.reason, status:0, debug:{
            stage:"static-skip",
            targetUrl,
            baseUrl:urlToStaticallyCheck,
            method
        }};
    }
    const g = await fastFetchProbe(page, targetUrl, method, postData, cookieHeader);
    const snippet = String(g.snippet || "");
    const ct = String((g.headers && g.headers["content-type"]) || "").toLowerCase();
    const htmlQuality = getHtmlQualitySignals(snippet);
    const clearHtml = hasClearHtmlStructure(snippet);
    const valuableErrorPage = hasValuableErrorPage(snippet);
    const debug = {
        stage:"probe",
        targetUrl,
        baseUrl:urlToStaticallyCheck,
        method,
        finalUrl: g.finalUrl || "",
        redirected: !!g.redirected,
        contentType: ct,
        bodyLength: snippet.length,
        hasClearHtmlStructure: clearHtml,
        hasValuableErrorPage: valuableErrorPage,
        htmlQuality,
        snippetPreview: snippet.replace(/\s+/g, " ").slice(0, 300)
    };
    if (!g.ok){
        return {skip:true, reason:"probe-failed", status:0, error: g.error, debug};
    }
    const status = g.status || 0;
    const s = snippet.toLowerCase();
    debug.status = status;
    if (g.headers && g.headers.location){
        debug.location = g.headers.location;
    }
    if (status >= 300 && status < 400){
        return {skip:true, reason:"redirect", status, headers: g.headers, debug};
    }
    if (status === 0){
        return {skip:true, reason:"opaque-redirect-or-network-error", status, headers: g.headers, debug};
    }
    if (status >= 400 && status < 500){
        return {skip:true, reason:"4xx", status, headers: g.headers, debug};
    }
    if (status >= 500 && status < 600){
        const signal5xx = hasValuable5xxSignals(g.snippet || "");
        debug.hasValuable5xxSignals = signal5xx.ok;
        debug.signal5xx = signal5xx;
        return {skip:!signal5xx.ok, reason: signal5xx.ok ? "5xx-valuable" : "5xx-no-signal", status, headers: g.headers, debug};
    }
    if (ct.includes("application/json") || ct.includes("javascript") || ct.includes("text/css") || ct.startsWith("image/") || ct.startsWith("font/")){
        return {skip:true, reason:"non-html", status, headers: g.headers, debug};
    }
    if (!(ct.includes("text/html") || ct.includes("text/plain") || ct === "")){
        return {skip:true, reason:"non-interactive-ct", status, headers: g.headers, debug};
    }
    const trimmedLength = s.trim().length;
    const bodyTooShort = trimmedLength > 0 && trimmedLength < FAST_MIN_NORMAL_BODY_BYTES;
    if (bodyTooShort){
        return {skip:true, reason:"short-body", status, headers: g.headers, debug};
    }
    if (!clearHtml){
        return {skip:true, reason:"no-clear-html-structure", status, headers: g.headers, debug};
    }
    const lowTextDensity = htmlQuality.textRatio > 0 && htmlQuality.textRatio < FAST_MIN_TEXT_RATIO;
    if (lowTextDensity && !valuableErrorPage){
        return {skip:true, reason:"low-text-density", status, headers: g.headers, debug};
    }
    return {skip:false, reason:"candidate", status, headers: g.headers, debug};
}

async function visit(page, targetUrl, method, postData, cookieHeader){
    let response = null;
    let responseText = "";
    try{
        await waitForPmRelogin(page);
        page.__lastRedirectAbortInfo = null;
        await page.setExtraHTTPHeaders(cookieHeader ? {"cookie": cookieHeader} : {});
        try{
            if (method === "GET"){
                response = await page.goto(targetUrl, {waitUntil:["domcontentloaded"], timeout: 15000});
            } else {
                page.__ov = {method:"POST", postData, cookieHeader, page};
                response = await page.goto(targetUrl, {waitUntil:["domcontentloaded"], timeout: 15000});
            }
        } finally {
            page.__ov = null;
        }
        if (!response){
            if (page.__lastRedirectAbortInfo){
                let status = page.__lastRedirectAbortInfo.status || 0;
                return {ok:false, valuable:false, status, redirected:true};
            }
            return {ok:false, valuable:false, status:0, redirected:false};
        }
        try{
            let ct = "";
            try{
                if (response.headers().hasOwnProperty("content-type")){
                    ct = response.headers()["content-type"] || "";
                }
            } catch(ex){
                ct = "";
            }
            if (ct.indexOf("text/") > -1 || ct.indexOf("html") > -1 || ct.indexOf("json") > -1){
                responseText = await withTimeout(response.text(), 3000);
            } else {
                responseText = "";
            }
        } catch(ex){
            try{
                responseText = await withTimeout(page.content(), 3000);
            } catch(ex2){
                responseText = "";
            }
        }
        let status = response.status();
        let redirected = false;
        try{
            let chain = response.request().redirectChain();
            redirected = chain && chain.length > 0;
        } catch(ex){
            redirected = false;
        }
        if (status >= 300 && status < 400){
            redirected = true;
        }
        if (redirected){
            return {ok:false, valuable:false, status, redirected:true};
        }
        
        let valuable = isInteractivePageQuiet(response, responseText);
        let hasBody = responseText && responseText.trim().length > 0;
        
        if (status >= 400){
            if (status >= 400 && status < 500){
                return {ok:false, valuable:false, status, redirected:false};
            }
            if (status >= 500 && status < 600){
                if (hasBody && hasValuable5xxSignals(responseText).ok){
                    return {ok:true, valuable:true, status, redirected:false};
                }
                return {ok:false, valuable:false, status, redirected:false};
            }
            return {ok:false, valuable:false, status, redirected:false};
        }
        
        return {ok:true, valuable, status, redirected:false};
    } catch(ex){
        return {ok:false, valuable:false, status:0, redirected:false};
    }
}

async function minimizeForUrl(page, baseUrl, allGet, allPost, allCookie, baseSite){
    let getParams = {...allGet};
    let postParams = {...allPost};
    let cookieParams = {...allCookie};

    function totalParamCount(){
        return Object.keys(postParams).length + Object.keys(cookieParams).length + Object.keys(getParams).length;
    }

    function removeKeys(obj, keys){
        let saved = {};
        for (let k of keys){
            if (Object.prototype.hasOwnProperty.call(obj, k)){
                saved[k] = obj[k];
                delete obj[k];
            }
        }
        return saved;
    }

    function restoreKeys(obj, saved){
        for (let k of Object.keys(saved)){
            obj[k] = saved[k];
        }
    }

    async function testCurrent(){
        let method = Object.keys(postParams).length > 0 ? "POST" : "GET";
        let targetUrl = buildUrlWithGet(baseUrl, getParams);
        let postBody = buildPostBody(postParams);
        let cookieStr = buildCookieString(cookieParams);
        let cookieHeader = mergeCookieHeaders(await cookiesToHeader(page, baseSite), cookieStr);
        return await visit(page, targetUrl, method, postBody, cookieHeader);
    }

    async function reduceLinear(obj, keys){
        for (let k of keys){
            let saved = removeKeys(obj, [k]);
            let r = await testCurrent();
            if (r.ok && r.valuable){
                continue;
            }
            restoreKeys(obj, saved);
        }
    }

    async function reduceBisection(obj, keys){
        async function rec(seg){
            if (seg.length === 0){
                return;
            }
            if (totalParamCount() < 10){
                await reduceLinear(obj, seg);
                return;
            }
            if (seg.length === 1){
                let saved = removeKeys(obj, seg);
                let r = await testCurrent();
                if (r.ok && r.valuable){
                    return;
                }
                restoreKeys(obj, saved);
                return;
            }
            let mid = Math.floor(seg.length / 2);
            let left = seg.slice(0, mid);
            let right = seg.slice(mid);
            let saved = removeKeys(obj, left);
            let r = await testCurrent();
            if (r.ok && r.valuable){
                await rec(right);
                return;
            }
            restoreKeys(obj, saved);
            await rec(left);
            await rec(right);
        }
        await rec(keys);
    }

    let baseRes = await testCurrent();
    if (!baseRes.ok || !baseRes.valuable){
        return {result:"skip", getParams, postParams, cookieParams, keepReason:"base-not-valuable-or-not-ok"};
    }

    if (totalParamCount() >= 10){
        await reduceBisection(postParams, Object.keys(postParams));
        await reduceBisection(cookieParams, Object.keys(cookieParams));
        await reduceBisection(getParams, Object.keys(getParams));
    }
    if (totalParamCount() < 10){
        await reduceLinear(postParams, Object.keys(postParams));
        await reduceLinear(cookieParams, Object.keys(cookieParams));
        await reduceLinear(getParams, Object.keys(getParams));
    }

    return {result:"add", getParams, postParams, cookieParams};
}

function ensureAflRequestData(baseAppdir){
    let fn = path.join(baseAppdir, "afl_request_data.json");
    if (!fs.existsSync(fn)){
        return {fn, data:{requestsFound:{}, inputSet:[]}};
    }
    let data = JSON.parse(fs.readFileSync(fn, "utf8"));
    if (!data.requestsFound || typeof data.requestsFound !== "object"){
        data.requestsFound = {};
    }
    if (!Array.isArray(data.inputSet)){
        data.inputSet = [];
    }
    return {fn, data};
}

function ensurePmProgress(baseAppdir){
    let fn = path.join(baseAppdir, "param_minimizer_progress.json");
    if (!fs.existsSync(fn)){
        return {fn, data:{completed:{}}};
    }
    let data = JSON.parse(fs.readFileSync(fn, "utf8"));
    if (!data || typeof data !== "object"){
        data = {};
    }
    if (!data.completed || typeof data.completed !== "object"){
        data.completed = {};
    }
    return {fn, data};
}

function markPmProgress(progressObj, url, status, error, location, debug){
    let entry = {
        done: true,
        status: status || "done",
        ts: Date.now()
    };
    if (error) entry.error = error;
    if (location) entry.location = location;
    if (debug && typeof debug === "object" && Object.keys(debug).length > 0) entry.debug = debug;
    progressObj.completed[url] = entry;
}

function nextId(requestsFound){
    let mx = 0;
    for (let v of Object.values(requestsFound)){
        if (v && typeof v === "object" && "_id" in v){
            let n = parseInt(v["_id"], 10);
            if (!Number.isNaN(n)){
                mx = Math.max(mx, n);
            }
        }
    }
    return mx + 1;
}

function addInputSet(inputSetArr, kvs){
    let s = new Set(inputSetArr);
    for (let kv of kvs){
        s.add(kv);
    }
    return Array.from(s);
}

function buildCookieHeaderFromParams(cookieParams){
    let cookieStr = buildCookieString(cookieParams);
    if (cookieStr.length === 0){
        return {};
    }
    return {"cookie": cookieStr};
}

function addRequestEntry(store, id, url, method, postData, headers){
    let fr = FoundRequest.requestParamFactory(url, method, postData || "", headers || {}, "initialParamMin", url);
    fr.from = "initialParamMin";
    let key = fr.getRequestKey();
    if (key in store){
        store[key]["attempts"] = 0;
        store[key]["processed"] = 0;
        store[key]["from"] = "initialParamMin";
        return false;
    }
    store[key] = {
        "_id": id,
        "_urlstr": fr.url(),
        "_url": fr.url(),
        "_resourceType": "document",
        "_method": method,
        "_postData": postData || "",
        "_headers": headers || {},
        "attempts": 0,
        "processed": 0,
        "from": "initialParamMin",
        "key": key,
    };
    return true;
}

function addInputSetForParams(inputSetArr, getParams, postParams, cookieParams){
    let kvs = [];
    for (let k of Object.keys(getParams || {})){ kvs.push(`${k}=${getParams[k]}`); }
    for (let k of Object.keys(postParams || {})){ kvs.push(`${k}=${postParams[k]}`); }
    for (let k of Object.keys(cookieParams || {})){ kvs.push(`${k}=${cookieParams[k]}`); }
    return addInputSet(inputSetArr, kvs);
}

function appendUniqueLine(linesArr, line){
    const s = String(line || "").trim();
    if (!s){
        return;
    }
    if (!linesArr.includes(s)){
        linesArr.push(s);
    }
}

async function setupPmPage(page){
    await page.setRequestInterception(true);
    page.__ov = null;
    page.__phase = "minimize";
    page.__lastRedirectAbortInfo = null;
    page.on("request", createOverrideHandler(() => page.__ov, () => page.__phase));
    await page.setCacheEnabled(false);
    await page.setDefaultNavigationTimeout(0);
}

async function main(){
    let cfg = parseArgs(process.argv);
    let urls = loadLines(cfg.urlsTxt);
    let params = loadParams(cfg.paramsJson);
    let allGet = pickFirstValues(params.GET);
    let allPost = pickFirstValues(params.POST);
    let allCookie = pickFirstValues(params.COOKIE);

    const appData = new AppData(true, cfg.baseAppdir, cfg.baseSite, cfg.headless);

    const browser = await puppeteer.launch({
        headless: cfg.headless,
        args: [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu"
        ]
    });
    const page = await browser.newPage();
    await setupPmPage(page);
    page.__phase = "login";

    let loginRes = await ensureLoggedIn(page, appData, cfg.baseAppdir);
    try{
        let lc = await page.cookies(cfg.baseSite);
        console.log(`[PM] login_cookie_count=${Array.isArray(lc) ? lc.length : 0}`);
        if (Array.isArray(lc) && lc.length > 0) {
            console.log(`[PM] cookies: ${lc.map(c => c.name + '=' + c.value).join('; ')}`);
        } else {
            console.log(`[PM] warning: no cookies found for ${cfg.baseSite}. Requests will likely be redirected to login.php`);
        }
    } catch(ex){
        console.log(`[PM] login_cookie_count=0 error=${ex}`);
    }
    if (loginRes.performed){
        if (loginRes.ok){
            console.log(`[PM] login=ok`);
        } else {
            console.log(`[PM] login=fail err=${loginRes.err || ""}`);
            await browser.close();
            process.exit(4);
        }
    } else {
        console.log(`[PM] login=skip`);
    }
    page.__phase = "minimize";

    let {fn, data} = ensureAflRequestData(cfg.baseAppdir);
    let {fn: progressFn, data: progressData} = ensurePmProgress(cfg.baseAppdir);
    let reqs = data.requestsFound;
    let nid = nextId(reqs);

    const loginCookies = await page.cookies(cfg.baseSite).catch(() => []);
    const workerPages = [page];
    for (let i = 1; i < 3; i++){
        const wp = await browser.newPage();
        await setupPmPage(wp);
        if (Array.isArray(loginCookies) && loginCookies.length > 0){
            try{ await wp.setCookie(...loginCookies); } catch(ex){}
        }
        workerPages.push(wp);
    }

    let added = 0;
    let skipCount = 0;
    let resumeSkipCount = 0;
    let idx = 0;
    let fullParamAcceptedUrls = [];
    
    let isReloggingIn = false;
    let loginRetryCount = 0;
    let sessionEpoch = 1;
    
    function isAuthRelatedUrl(rawUrl){
        try{
            const u = new URL(String(rawUrl || ""), cfg.baseSite);
            const p = `${u.pathname || ""}${u.search || ""}`.toLowerCase();
            return p.includes("login") || p.includes("logout") || p.includes("signout") || p.includes("logoff") || p.includes("index.php");
        } catch(ex){
            const s = String(rawUrl || "").toLowerCase();
            return s.includes("login") || s.includes("logout") || s.includes("signout") || s.includes("logoff") || s.includes("index.php");
        }
    }
    
    function isLoginExpiryRedirect(baseUrl, pre, configLoginUrl){
        if (!pre || !pre.skip || pre.reason !== "redirect" || !pre.headers || !pre.headers.location){
            return false;
        }
        if (isAuthRelatedUrl(baseUrl)){
            return false;
        }
        const loc = String(pre.headers.location || "").toLowerCase();
        const cfgLogin = String(configLoginUrl || "").toLowerCase();
        const isMatchConfig = cfgLogin && (loc.endsWith(cfgLogin) || cfgLogin.endsWith(loc));
        return !!(isMatchConfig || loc.includes("login") || loc.includes("index.php"));
    }
    
    async function waitForReloginIdle(tag="") {
        let announced = false;
        while (isReloggingIn) {
            if (!announced && tag){
                console.log(`[PM-DEBUG] Waiting for re-login to finish before ${tag}...`);
                announced = true;
            }
            await new Promise(r => setTimeout(r, 200));
        }
    }
    for (let wp of workerPages) {
        wp.__pmWaitWhileRelogin = () => waitForReloginIdle(`network activity on ${wp.__phase || "unknown-phase"}`);
    }
    
    async function reLoginAllWorkers() {
        if (isReloggingIn) {
            console.log(`[PM] Already re-logging in. Waiting for other worker to finish...`);
            let waitLimit = 60; // Wait up to 30 seconds
            while (isReloggingIn && waitLimit > 0) {
                await new Promise(r => setTimeout(r, 500));
                waitLimit--;
            }
            return true;
        }
        
        loginRetryCount++;
        if (loginRetryCount > 5) {
            console.log(`[PM] Max re-login attempts exceeded. Aborting re-login.`);
            return false;
        }
        
        isReloggingIn = true;
        try {
            console.log(`[PM] Detected login session expiration. Re-logging in...`);
            console.log(`[PM-DEBUG] reLoginAllWorkers start retry=${loginRetryCount} workerCount=${workerPages.length}`);
            
            // Critical fix: We must clear the browser's persistent state and ensure we are on the login page
            // BEFORE calling ensureLoggedIn, because input_sifter2's do_login expects a clean slate.
            for (let wp of workerPages) {
                try {
                    wp.__phase = "login";
                    let wpUrl = "";
                    try{ wpUrl = await wp.url(); } catch(innerEx){}
                    let oldCookies = await wp.cookies(cfg.baseSite);
                    console.log(`[PM-DEBUG] Worker pre-relogin phase=${wp.__phase || "-"} url=${wpUrl || "-"} cookieCount=${Array.isArray(oldCookies) ? oldCookies.length : 0}`);
                    if (oldCookies && oldCookies.length > 0) {
                        await wp.deleteCookie(...oldCookies);
                        console.log(`[PM-DEBUG] Cleared ${oldCookies.length} old cookies from a worker page.`);
                    }
                } catch(e){
                    console.log(`[PM-DEBUG] Error clearing cookies: ${e}`);
                }
            }
            
            // Navigate the main page to about:blank to clear any weird DOM state/event listeners
            try {
                console.log(`[PM-DEBUG] Navigating main page to about:blank to reset DOM state...`);
                await page.goto("about:blank", {waitUntil: "domcontentloaded", timeout: 5000});
                console.log(`[PM-DEBUG] Main page reset successful. Initiating ensureLoggedIn...`);
            } catch(e){
                console.log(`[PM-DEBUG] Error navigating to about:blank: ${e}`);
            }

            let loginRes;
            try {
                loginRes = await ensureLoggedIn(page, appData, cfg.baseAppdir);
            } catch (innerEx) {
                console.log(`[PM-DEBUG] ensureLoggedIn threw an exception: ${innerEx.stack || innerEx}`);
                loginRes = { ok: false, err: String(innerEx) };
            }
            if (!loginRes.ok) {
                console.log(`[PM-DEBUG] Re-login failed internally: ${loginRes.err}`);
                console.log(`[PM-DEBUG] Trying alternative fallback login strategy via worker pages...`);
                // If main page failed, maybe it's completely stuck. Try using one of the worker pages instead.
                if (workerPages.length > 1) {
                    try {
                        let fallbackPage = workerPages[1];
                        fallbackPage.__phase = "login";
                        await fallbackPage.goto("about:blank", {waitUntil: "domcontentloaded", timeout: 5000});
                        let fallbackRes;
                        try {
                            fallbackRes = await ensureLoggedIn(fallbackPage, appData, cfg.baseAppdir);
                        } catch (fallbackInnerEx) {
                            console.log(`[PM-DEBUG] Fallback ensureLoggedIn threw: ${fallbackInnerEx.stack || fallbackInnerEx}`);
                            fallbackRes = { ok: false, err: String(fallbackInnerEx) };
                        }
                        if (!fallbackRes.ok) {
                            console.log(`[PM-DEBUG] Fallback re-login also failed: ${fallbackRes.err}`);
                            return false;
                        } else {
                            console.log(`[PM-DEBUG] Fallback re-login succeeded on worker page!`);
                            // Sync cookies back to main page and other workers
                            const fallbackCookies = await fallbackPage.cookies(cfg.baseSite).catch(() => []);
                            if (Array.isArray(fallbackCookies) && fallbackCookies.length > 0) {
                                for (let wp of workerPages) {
                                    wp.__phase = "minimize";
                                    if (wp !== fallbackPage) {
                                        try { await wp.setCookie(...fallbackCookies); } catch(ex){}
                                    }
                                }
                                sessionEpoch += 1;
                                console.log(`[PM] Re-login successful via fallback. New cookies distributed.`);
                                return true;
                            }
                        }
                    } catch(ex) {
                        console.log(`[PM-DEBUG] Fallback exception: ${ex}`);
                        return false;
                    }
                }
                return false;
            }
            const newCookies = await page.cookies(cfg.baseSite).catch(() => []);
            if (Array.isArray(newCookies) && newCookies.length > 0) {
                for (let wp of workerPages) {
                    wp.__phase = "minimize";
                    if (wp !== page) {
                        try { await wp.setCookie(...newCookies); } catch(ex){}
                    }
                }
                sessionEpoch += 1;
                console.log(`[PM] Re-login successful. New cookies distributed to all workers.`);
                return true;
            }
            for (let wp of workerPages) {
                wp.__phase = "minimize";
            }
            return false;
        } finally {
            for (let wp of workerPages) {
                try{ wp.__phase = "minimize"; } catch(ex){}
            }
            isReloggingIn = false;
        }
    }

    async function processOne(workerPage, baseUrl){
        await waitForReloginIdle(`processing ${baseUrl}`);
        if (progressData.completed && progressData.completed[baseUrl] && progressData.completed[baseUrl].done){
            resumeSkipCount += 1;
            return;
        }
        const localSessionEpoch = sessionEpoch;
        const t0 = Date.now();
        
        const staticSkip = shouldStaticSkipUrl(baseUrl);
        
        let isLoginRedirect = false;
        let loginUrl = "";
        let configLoginUrl = "";
        try {
            let loginDataFile = path.join(cfg.baseAppdir, "login.json");
            if (fs.existsSync(loginDataFile)) {
                let ldata = JSON.parse(fs.readFileSync(loginDataFile, "utf8"));
                configLoginUrl = ldata.form_url || "";
            }
        } catch (ex) {}

        async function buildProgressDebug(pre, reqMethod, reqUrl, reqPostData, reqCookieHeader){
            let currentUrl = "";
            let pageCookieNames = [];
            let pageCookieCount = 0;
            try{ currentUrl = await workerPage.url(); } catch(ex){}
            try{
                const cks = await workerPage.cookies(cfg.baseSite);
                pageCookieCount = Array.isArray(cks) ? cks.length : 0;
                pageCookieNames = Array.isArray(cks) ? cks.map(c => c.name) : [];
            } catch(ex){
            }
            return {
                requestUrl: reqUrl,
                requestMethod: reqMethod,
                requestPostData: reqPostData || "",
                requestCookieHeaderLength: String(reqCookieHeader || "").length,
                workerPhase: workerPage.__phase || "",
                workerCurrentUrl: currentUrl,
                workerCookieCount: pageCookieCount,
                workerCookieNames: pageCookieNames,
                probe: pre && pre.debug ? pre.debug : undefined
            };
        }

        if (staticSkip.skip){
            skipCount += 1;
            const debug = await buildProgressDebug({
                debug:{
                    stage:"static-skip",
                    targetUrl: baseUrl,
                    baseUrl,
                    method:"GET",
                    reason: staticSkip.reason
                }
            }, "GET", baseUrl, "", "");
            markPmProgress(progressData, baseUrl, `pre-${staticSkip.reason}`, "", undefined, debug);
            fs.writeFileSync(progressFn, JSON.stringify(progressData, null, 2));
            console.log(`[PM] skip url=${baseUrl} reason=${staticSkip.reason} status=0 err= ms=${Date.now() - t0}`);
            return;
        }
        
        const baseCookieHeader = await cookiesToHeader(workerPage, cfg.baseSite);
        const noParamPre = await quickPrecheck(workerPage, baseUrl, "GET", "", baseCookieHeader, baseUrl);
        if (sessionEpoch !== localSessionEpoch){
            console.log(`[PM-DEBUG] Discard stale no-param probe result for ${baseUrl}; session epoch changed ${localSessionEpoch}->${sessionEpoch}`);
            return await processOne(workerPage, baseUrl);
        }
        
        if (!noParamPre.skip){
            const id = nid;
            nid += 1;
            const headers = baseCookieHeader ? {"cookie": baseCookieHeader} : {};
            const wasAdded = addRequestEntry(reqs, id, baseUrl, "GET", "", headers);
            if (wasAdded) added += 1;
            console.log(`[PM] add url=${baseUrl} method=GET get=0 post=0 cookie=0 keepReason=pass-without-params ms=${Date.now() - t0}`);
            markPmProgress(progressData, baseUrl, "add");
            fs.writeFileSync(progressFn, JSON.stringify(progressData, null, 2));
            return;
        }
        
        if (noParamPre.status >= 400 && noParamPre.status < 600){
            skipCount += 1;
            const loc = noParamPre.headers && noParamPre.headers.location ? noParamPre.headers.location : undefined;
            const debug = await buildProgressDebug(noParamPre, "GET", baseUrl, "", baseCookieHeader);
            markPmProgress(progressData, baseUrl, `pre-${noParamPre.reason}`, noParamPre.error, loc, debug);
            fs.writeFileSync(progressFn, JSON.stringify(progressData, null, 2));
            console.log(`[PM] skip url=${baseUrl} reason=${noParamPre.reason} status=${noParamPre.status || 0} err=${noParamPre.error || ""} ms=${Date.now() - t0}`);
            return;
        }

        try {
            if (isLoginExpiryRedirect(baseUrl, noParamPre, configLoginUrl)) {
                isLoginRedirect = true;
                loginUrl = noParamPre.headers.location;
            }
        } catch (ex) {}

        if (isLoginRedirect) {
            console.log(`[PM-DEBUG] Login expiry suspected for ${baseUrl} redirecting to ${loginUrl || "-"}. Triggering single global re-login.`);
            let reLoginSuccess = await reLoginAllWorkers();
            if (reLoginSuccess) {
                return await processOne(workerPage, baseUrl);
            }
        }

        const hasAnyParam = Object.keys(allGet).length > 0 || Object.keys(allPost).length > 0 || Object.keys(allCookie).length > 0;
        if (!hasAnyParam){
            skipCount += 1;
            const debug = await buildProgressDebug(noParamPre, "GET", baseUrl, "", baseCookieHeader);
            markPmProgress(progressData, baseUrl, `skip-${noParamPre.reason || "no-params-and-no-value"}`, noParamPre.error, undefined, debug);
            fs.writeFileSync(progressFn, JSON.stringify(progressData, null, 2));
            console.log(`[PM] skip url=${baseUrl} reason=${noParamPre.reason || "no-params-and-no-value"} status=${noParamPre.status || 0} err=${noParamPre.error || ""} ms=${Date.now() - t0}`);
            return;
        }

        const fullMethod = Object.keys(allPost).length > 0 ? "POST" : "GET";
        const fullUrl = buildUrlWithGet(baseUrl, allGet);
        const fullPostData = buildPostBody(allPost);
        const fullCookieHeader = mergeCookieHeaders(await cookiesToHeader(workerPage, cfg.baseSite), buildCookieString(allCookie));
        const fullPre = await quickPrecheck(workerPage, fullUrl, fullMethod, fullPostData, fullCookieHeader, baseUrl);
        if (sessionEpoch !== localSessionEpoch){
            console.log(`[PM-DEBUG] Discard stale full-param probe result for ${baseUrl}; session epoch changed ${localSessionEpoch}->${sessionEpoch}`);
            return await processOne(workerPage, baseUrl);
        }
        if (isLoginExpiryRedirect(baseUrl, fullPre, configLoginUrl)){
            console.log(`[PM-DEBUG] Login expiry suspected during full-param probe for ${baseUrl}. Triggering single global re-login.`);
            let reLoginSuccess = await reLoginAllWorkers();
            if (reLoginSuccess) {
                return await processOne(workerPage, baseUrl);
            }
        }
        if (fullPre.skip){
            skipCount += 1;
            const loc = fullPre.headers && fullPre.headers.location ? fullPre.headers.location : undefined;
            const debug = await buildProgressDebug(fullPre, fullMethod, fullUrl, fullPostData, fullCookieHeader);
            markPmProgress(progressData, baseUrl, `pre-full-${fullPre.reason}`, fullPre.error, loc, debug);
            fs.writeFileSync(progressFn, JSON.stringify(progressData, null, 2));
            console.log(`[PM] skip url=${baseUrl} reason=full-${fullPre.reason} status=${fullPre.status || 0} err=${fullPre.error || ""} ms=${Date.now() - t0}`);
            return;
        }

        let curGet = {...allGet};
        let curPost = {...allPost};
        let curCookie = {...allCookie};
        await waitForReloginIdle(`minimizing ${baseUrl}`);
        const min = await withTimeout(minimizeForUrl(workerPage, baseUrl, curGet, curPost, curCookie, cfg.baseSite), 25000).catch(() => null);
        const finalMin = min && min.result === "add" ? min : {
            result: "add",
            getParams: {...curGet},
            postParams: {...curPost},
            cookieParams: {...curCookie},
            keepReason: "min-timeout-or-error"
        };
        if (min && min.result === "skip"){
            skipCount += 1;
            const cookieHeader = mergeCookieHeaders(await cookiesToHeader(workerPage, cfg.baseSite), buildCookieString(curCookie));
            const debug = await buildProgressDebug({
                status: min.status || 0,
                error: min.error,
                headers: min.headers || {},
                debug: {
                    stage:"min-base-check",
                    targetUrl: baseUrl,
                    baseUrl,
                    method: Object.keys(curPost).length > 0 ? "POST" : "GET",
                    keepReason: min.keepReason || "base-not-valuable-or-not-ok"
                }
            }, Object.keys(curPost).length > 0 ? "POST" : "GET", buildUrlWithGet(baseUrl, curGet), buildPostBody(curPost), cookieHeader);
            markPmProgress(progressData, baseUrl, `skip-${min.keepReason || "base-not-valuable-or-not-ok"}`, min.error || "", undefined, debug);
            fs.writeFileSync(progressFn, JSON.stringify(progressData, null, 2));
            console.log(`[PM] skip url=${baseUrl} reason=${min.keepReason || "base-not-valuable-or-not-ok"} status=${min.status || 0} err=${min.error || ""} ms=${Date.now() - t0}`);
            return;
        }
        const urlWithGet = buildUrlWithGet(baseUrl, finalMin.getParams);
        const method = Object.keys(finalMin.postParams).length > 0 ? "POST" : "GET";
        const postData = buildPostBody(finalMin.postParams);
        const headers = buildCookieHeaderFromParams(finalMin.cookieParams);
        const id = nid;
        nid += 1;
        const wasAdded = addRequestEntry(reqs, id, urlWithGet, method, postData, headers);
        if (wasAdded){
            added += 1;
        }
        console.log(`[PM] add url=${baseUrl} method=${method} get=${Object.keys(finalMin.getParams).length} post=${Object.keys(finalMin.postParams).length} cookie=${Object.keys(finalMin.cookieParams).length} keepReason=${finalMin.keepReason || "-"} ms=${Date.now() - t0}`);
        data.inputSet = addInputSetForParams(data.inputSet, finalMin.getParams, finalMin.postParams, finalMin.cookieParams);
        markPmProgress(progressData, baseUrl, "add");
        fs.writeFileSync(progressFn, JSON.stringify(progressData, null, 2));
    }
    async function workerLoop(workerPage){
        while (true){
            let cur = idx;
            idx += 1;
            if (cur >= urls.length){
                break;
            }
            await processOne(workerPage, urls[cur]);
        }
    }
    await Promise.all(workerPages.map(p => workerLoop(p)));

    fs.writeFileSync(fn, JSON.stringify(data, null, 2));
    if (cfg.fullParamsOutput){
        fs.writeFileSync(cfg.fullParamsOutput, fullParamAcceptedUrls.join("\n") + (fullParamAcceptedUrls.length > 0 ? "\n" : ""), "utf8");
    }
    console.log(`[PM] completed urls_in=${urls.length} added=${added} skip=${skipCount} resume_skip=${resumeSkipCount} afl_request_data=${fn}`);

    await browser.close();
}

main().catch((e) => {
    console.log("param_minimizer error", e);
    process.exit(3);
});
