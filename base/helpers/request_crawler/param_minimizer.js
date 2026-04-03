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
    args = args.filter((a) => {
        if (a === "--no-headless"){
            headless = false;
            return false;
        }
        return true;
    });
    if (args.length > 0 && (args[0] === "request_crawler" || args[0] === "request-crawler")){
        args = args.slice(1);
    }
    if (args.length < 4){
        console.log("Usage:\n\tnode param_minimizer.js [request_crawler] BASE_SITE BASE_APPDIR URLS_TXT PARAMS_JSON [--no-headless]\n");
        process.exit(2);
    }
    return {
        baseSite: args[0],
        baseAppdir: args[1],
        urlsTxt: args[2],
        paramsJson: args[3],
        headless,
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

async function ensureLoggedIn(page, appData, baseAppdir){
    let tmpApp = appData;
    tmpApp.requestsFound = {};
    tmpApp.seedRequestsFound = {};
    tmpApp.collectedURL = 0;
    let re = new RequestExplorer(tmpApp, 0, baseAppdir, null);
    if (re.loginData !== undefined && "form_url" in re.loginData){
        try{
            await re.do_login(page, {attachInterceptor:false});
            return {performed:true, ok:true};
        } catch(ex){
            return {performed:true, ok:false, err: (ex && ex.message) ? ex.message : String(ex)};
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
    if (responseText.search(/<body[ >]/) > -1 || responseText.search(/<form[ >]/) > -1 || responseText.search(/<frameset[ >]/) > -1 ){
        return true;
    }
    return false;
}

function createOverrideHandler(getOverride){
    return async function(req){
        try{
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

async function visit(page, targetUrl, method, postData, cookieHeader){
    let response = null;
    let responseText = "";
    try{
        await page.setExtraHTTPHeaders(cookieHeader ? {"cookie": cookieHeader} : {});
        if (method === "GET"){
            response = await page.goto(targetUrl, {waitUntil:["domcontentloaded"], timeout: 30000});
        } else {
            page.__ov = {method:"POST", postData, cookieHeader, page};
            response = await page.goto(targetUrl, {waitUntil:["domcontentloaded"], timeout: 30000});
            page.__ov = null;
        }
        if (!response){
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
                responseText = await withTimeout(response.text(), 5000);
            } else {
                responseText = "";
            }
        } catch(ex){
            try{
                responseText = await withTimeout(page.content(), 5000);
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
        if (status >= 400){
            return {ok:false, valuable:false, status, redirected:false};
        }
        let valuable = isInteractivePageQuiet(response, responseText);
        return {ok:true, valuable, status, redirected:false};
    } catch(ex){
        return {ok:false, valuable:false, status:0, redirected:false};
    }
}

async function minimizeForUrl(page, baseUrl, allGet, allPost, allCookie, baseSite){
    let getParams = {...allGet};
    let postParams = {...allPost};
    let cookieParams = {...allCookie};

    let method = Object.keys(postParams).length > 0 ? "POST" : "GET";
    let targetUrl = buildUrlWithGet(baseUrl, getParams);
    let postBody = buildPostBody(postParams);
    let cookieStr = buildCookieString(cookieParams);
    let cookieHeader = mergeCookieHeaders(await cookiesToHeader(page, baseSite), cookieStr);

    let baseRes = await visit(page, targetUrl, method, postBody, cookieHeader);
    if (!baseRes.ok || !baseRes.valuable){
        return {result:"skip", stage:"base", ok:baseRes.ok, valuable:baseRes.valuable, status:baseRes.status, redirected:baseRes.redirected};
    }

    let keysGet = Object.keys(getParams);
    for (let k of keysGet){
        let saved = getParams[k];
        delete getParams[k];
        targetUrl = buildUrlWithGet(baseUrl, getParams);
        postBody = buildPostBody(postParams);
        cookieStr = buildCookieString(cookieParams);
        cookieHeader = mergeCookieHeaders(await cookiesToHeader(page, baseSite), cookieStr);
        let r = await visit(page, targetUrl, method, postBody, cookieHeader);
        if (r.ok && r.valuable){
            continue;
        }
        getParams[k] = saved;
    }

    let keysPost = Object.keys(postParams);
    for (let k of keysPost){
        let saved = postParams[k];
        delete postParams[k];
        method = Object.keys(postParams).length > 0 ? "POST" : "GET";
        targetUrl = buildUrlWithGet(baseUrl, getParams);
        postBody = buildPostBody(postParams);
        cookieStr = buildCookieString(cookieParams);
        cookieHeader = mergeCookieHeaders(await cookiesToHeader(page, baseSite), cookieStr);
        let r = await visit(page, targetUrl, method, postBody, cookieHeader);
        if (r.ok && r.valuable){
            continue;
        }
        postParams[k] = saved;
    }

    let keysCookie = Object.keys(cookieParams);
    for (let k of keysCookie){
        let saved = cookieParams[k];
        delete cookieParams[k];
        method = Object.keys(postParams).length > 0 ? "POST" : "GET";
        targetUrl = buildUrlWithGet(baseUrl, getParams);
        postBody = buildPostBody(postParams);
        cookieStr = buildCookieString(cookieParams);
        cookieHeader = mergeCookieHeaders(await cookiesToHeader(page, baseSite), cookieStr);
        let r = await visit(page, targetUrl, method, postBody, cookieHeader);
        if (r.ok && r.valuable){
            continue;
        }
        cookieParams[k] = saved;
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
    await page.setRequestInterception(true);
    page.__ov = null;
    page.on("request", createOverrideHandler(() => page.__ov));
    await page.setCacheEnabled(false);
    await page.setDefaultNavigationTimeout(0);

    let loginRes = await ensureLoggedIn(page, appData, cfg.baseAppdir);
    if (loginRes.performed){
        if (loginRes.ok){
            console.log(`[PM] login=ok`);
        } else {
            console.log(`[PM] login=fail err=${loginRes.err || ""}`);
        }
    } else {
        console.log(`[PM] login=skip`);
    }

    let {fn, data} = ensureAflRequestData(cfg.baseAppdir);
    let reqs = data.requestsFound;
    let nid = nextId(reqs);

    let added = 0;
    for (let baseUrl of urls){
        let t0 = Date.now();
        let min = await withTimeout(minimizeForUrl(page, baseUrl, allGet, allPost, allCookie, cfg.baseSite), 45000).catch(() => null);
        if (!min || min.result === "skip"){
            let status = min && typeof min.status !== "undefined" ? min.status : 0;
            let ms = Date.now() - t0;
            let redir = min && min.redirected ? 1 : 0;
            console.log(`[PM] url=${baseUrl} result=skip status=${status} redir=${redir} ms=${ms}`);
            continue;
        }
        let urlWithGet = buildUrlWithGet(baseUrl, min.getParams);
        let method = Object.keys(min.postParams).length > 0 ? "POST" : "GET";
        let postData = buildPostBody(min.postParams);
        let headers = buildCookieHeaderFromParams(min.cookieParams);
        let wasAdded = addRequestEntry(reqs, nid, urlWithGet, method, postData, headers);
        nid += 1;
        if (wasAdded){
            added += 1;
        }
        let ms = Date.now() - t0;
        console.log(`[PM] url=${baseUrl} result=add method=${method} get=${Object.keys(min.getParams).length} post=${Object.keys(min.postParams).length} cookie=${Object.keys(min.cookieParams).length} ms=${ms}`);

        let kvs = [];
        for (let k of Object.keys(min.getParams)){
            kvs.push(`${k}=${min.getParams[k]}`);
        }
        for (let k of Object.keys(min.postParams)){
            kvs.push(`${k}=${min.postParams[k]}`);
        }
        for (let k of Object.keys(min.cookieParams)){
            kvs.push(`${k}=${min.cookieParams[k]}`);
        }
        data.inputSet = addInputSet(data.inputSet, kvs);
    }

    fs.writeFileSync(fn, JSON.stringify(data, null, 2));
    console.log(`[PM] completed urls_in=${urls.length} added=${added} afl_request_data=${fn}`);

    await browser.close();
}

main().catch((e) => {
    console.log("param_minimizer error", e);
    process.exit(3);
});
