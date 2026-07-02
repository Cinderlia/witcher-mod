//import puppeteer from 'puppeteer';

import puppeteer from 'puppeteer';
import fs from 'fs';
import path from 'path';
import http from 'http';
import urlExist from "url-exist"
import process from 'process';
import fuzzySet from 'fuzzyset';
//const {JSHandle} = require('puppeteer/lib');
import {FoundRequest} from './FoundRequest.js';
import {fileURLToPath} from 'url';

import{ networkInterfaces } from 'os';

const GREEN="\x1b[38;5;2m";
const ENDCOLOR="\x1b[0m";

const MAX_NUM_ROUNDS = 3;
const MAIN_SLICE_QUOTA = 4;
const SEED_SLICE_QUOTA = 1;
const TOTAL_SLICE_QUOTA = MAIN_SLICE_QUOTA + SEED_SLICE_QUOTA;

let SIGINT_HANDLER_INSTALLED = false;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const GREMLINS_LOCAL_PATH = path.join(__dirname, "gremlins.min.js");

// var requestsFound = {}; // { <method+url>: {url:"", method:"", postData:"", attempts:0 } }
function sleepg(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export class AppData{

    constructor(initializeWithBase, base_appdir, base_site, headless) {
        this.requestsFound = {};
        this.seedRequestsFound = {};

        this.site_url = new URL(base_site);
        this.headless = headless;
        this.inputSet = new Set();
        this.meta = {init:{}};
        this.currentURLRound = 1;
        this.seedURLRound = 1;
        this._timeSliceIndex = 0;
        this.collectedURL = 0;
        this.base_appdir = base_appdir;
        this.usingFuzzingDir = false;
        this.maxKeyMatches = 2;
        this.fuzzyMatchEquivPercent = .70;
        this.ignoreValues = new Set();
        this.urlUniqueIfValueUnique = new Set();
        this.minFuzzyScore = .80;
        this.ips = ["127.0.0.1", "localhost", this.site_url.host]
        this.gremlinValues = new Set(["Witcher","127.0.0.1", "W'tcher","W%27tcher","2"]);
        const nets = networkInterfaces();
        for (const name of Object.keys(nets)) {
            for (const net of nets[name]) {
                this.ips.push(net.address)
            }
        }
        
        this.site_ip = this.site_url.host
        //this.site_ip = base_site.

        this.loadReqsFromJSON();
        if (!this.meta || !this.meta.hasOwnProperty("init")){
            this.meta = {init:{}};
        }
        let totalQueued = this.reqCount + this.seedCount;
        let startupLine = `[WC][DEBUG] AppData after load: main=${this.reqCount} seed=${this.seedCount} currentRound=${this.currentURLRound} seedRound=${this.seedURLRound}`;
        console.log(startupLine);
        this._startupLog(startupLine);
        if (!this.meta.init || this.meta.init["crawler_default"] !== true || totalQueued === 0){
            this._performCrawlerDefaultInit();
            if (this.meta && this.meta.init){
                this.meta.init["crawler_default"] = true;
            }
            this.save();
            let initLine = `[WC][DEBUG] AppData default init complete: main=${this.reqCount} seed=${this.seedCount}`;
            console.log(initLine);
            this._startupLog(initLine);
        }
    }

    _startupLog(msg){
        try{
            let fn = path.join(this.base_appdir, "crawler_startup.log");
            let line = `[${(new Date()).toISOString()}] ${msg}\n`;
            fs.appendFileSync(fn, line, {encoding:"utf8"});
        } catch(ex){
        }
    }

    _performCrawlerDefaultInit(){
        /**
         * Adding extra guessed urls here.
         */
        try{
            let baseHref = this.site_url.href;
            let adminHref = (new URL("admin", baseHref)).href;
            this.addRequest(FoundRequest.requestParamFactory(adminHref, "GET", "",{},"initial",baseHref))
            this.addRequest(FoundRequest.requestParamFactory(baseHref, "GET", "",{},"initial",baseHref))
        } catch(ex){
            if (this.site_url.href.endsWith("/")){
                this.addRequest(FoundRequest.requestParamFactory(`${this.site_url.href}/admin`, "GET", "",{},"initial",this.site_url.href))
            }
            this.addRequest(FoundRequest.requestParamFactory(`${this.site_url.href}`, "GET", "",{},"initial",this.site_url.href))
        }
        this.seedLocalPhpFiles();
        this.updateReqsFromExternal();
    }

    seedLocalPhpFiles(){
        try{
            let pathname = this.site_url.pathname || "/";
            let trimmed = pathname.replace(/^\/+/, "").replace(/\/+$/, "");
            if (trimmed.length === 0){
                console.log(`[WC][DEBUG] seedLocalPhpFiles: empty pathname from base_site=${this.site_url.href}`);
                return;
            }
            let segments = trimmed.split("/").filter(s => s.length > 0);
            let candidateDirs = [
                path.join(this.base_appdir, ...segments),
                path.join(this.base_appdir, "app", ...segments),
            ];
            let localBaseDir = "";
            for (let cand of candidateDirs){
                if (fs.existsSync(cand)){
                    localBaseDir = cand;
                    break;
                }
            }
            if (localBaseDir.length === 0){
                console.log(`[WC][DEBUG] seedLocalPhpFiles: no local dir found for pathname=${pathname} base_site=${this.site_url.href} base_appdir=${this.base_appdir}`);
                for (let cand of candidateDirs){
                    console.log(`[WC][DEBUG] seedLocalPhpFiles: tried ${cand}`);
                }
                return;
            }
            if (!fs.existsSync(localBaseDir)){
                console.log(`[WC][DEBUG] seedLocalPhpFiles: local dir not found: ${localBaseDir} (base_site=${this.site_url.href})`);
                return;
            }
            if (!fs.lstatSync(localBaseDir).isDirectory()){
                console.log(`[WC][DEBUG] seedLocalPhpFiles: local path is not a directory: ${localBaseDir}`);
                return;
            }

            let phpFilesAbs = [];
            let walk = (dir) => {
                let entries = fs.readdirSync(dir, {withFileTypes:true});
                entries.sort((a,b) => a.name.localeCompare(b.name));
                for (let ent of entries){
                    let full = path.join(dir, ent.name);
                    if (ent.isDirectory()){
                        walk(full);
                        continue;
                    }
                    if (ent.isFile() && ent.name.toLowerCase().endsWith(".php")){
                        phpFilesAbs.push(full);
                    }
                }
            };
            walk(localBaseDir);

            console.log(`[WC][DEBUG] seedLocalPhpFiles: base_site=${this.site_url.href} localBaseDir=${localBaseDir} phpCount=${phpFilesAbs.length}`);
            if (phpFilesAbs.length === 0){
                return;
            }

            let baseHref = this.site_url.href.endsWith("/") ? this.site_url.href : (this.site_url.href + "/");
            let added = 0;
            for (let absFn of phpFilesAbs){
                let rel = path.relative(localBaseDir, absFn).replace(/\\/g, "/");
                if (rel.length === 0){
                    continue;
                }
                let urlHref = new URL(rel, baseHref).href;
                let fr = FoundRequest.requestParamFactory(urlHref, "GET", "", {}, "initialLocalPHP", this.site_url.href);
                fr.from = "initialLocalPHP";
                if (this.addRequest(fr)){
                    added++;
                    console.log(`[WC][DEBUG] seedLocalPhpFiles: added url=${urlHref} file=${absFn}`);
                }
            }
            console.log(`[WC][DEBUG] seedLocalPhpFiles: added=${added}`);
        } catch(ex){
            console.log(`[WC][DEBUG] seedLocalPhpFiles: error base_site=${this.site_url.href} base_appdir=${this.base_appdir}`);
            console.log(ex);
        }
    }
    addGremlinValue(newval){
        this.gremlinValues.add(newval);
    }
    updateReqsFromExternal(){
        let extra_reqs_json_fn = path.join(this.base_appdir, "afl_request_data.json");
        if (fs.existsSync(extra_reqs_json_fn)){
            let jstrdata = fs.readFileSync(extra_reqs_json_fn);
            let parsed = JSON.parse(jstrdata);
            let temprf = parsed;
            if (parsed && typeof parsed === "object" && parsed.hasOwnProperty("requestsFound")){
                temprf = parsed["requestsFound"];
            }
            if (!temprf || typeof temprf !== "object"){
                return;
            }
            this.currentURLRound = 0;
            this.seedURLRound = 0;
            for (let key of Object.keys(temprf)){
                let req = temprf[key];
                if (key in this.requestsFound || key in this.seedRequestsFound){
                    // skip
                } else {
                    this.seedRequestsFound[key] = Object.assign(new FoundRequest(), req);
                    this.seedRequestsFound[key]["attempts"] = 0
                    console.log("NEW SEED REQ FND from scanner", this.seedRequestsFound[key].toString());
                }
                
            }
        }
    }
    loadReqsFromJSON() {
        let json_fn = path.join(this.base_appdir, "request_data.json");
        
        if (fs.existsSync(json_fn)) {
            console.log(" ************************* LOADING INCOMING ******************************");
            let jstrdata = fs.readFileSync(json_fn);
            let jdata = JSON.parse(jstrdata);
            if (jdata && typeof jdata === "object" && jdata.hasOwnProperty("_witcher_meta")){
                this.meta = jdata["_witcher_meta"];
            }
            if (!this.meta || typeof this.meta !== "object"){
                this.meta = {init:{}};
            }
            if (!this.meta.hasOwnProperty("init") || typeof this.meta.init !== "object"){
                this.meta.init = {};
            }
            if (Array.isArray(jdata["inputSet"])){
                this.inputSet = new Set(jdata["inputSet"]);
            } else {
                this.inputSet = new Set();
            }
            let temprf = jdata["requestsFound"];
            if (!temprf || typeof temprf !== "object"){
                temprf = {};
            }
            let tempSeed = jdata["seedRequestsFound"];
            if (!tempSeed || typeof tempSeed !== "object"){
                tempSeed = {};
            }
            let keys = Object.keys(temprf);
            console.log(`[WC][DEBUG] loadReqsFromJSON: loaded=${keys.length} file=${json_fn}`);
            let preview = keys.length <= 50;
            let previewLimit = 5;
            let printed = 0;
            for (let key of keys){
                let req = temprf[key];
                let att = 0;
                if (req && typeof req === "object" && req.hasOwnProperty("attempts")){
                    att = req["attempts"];
                }
                if (typeof att !== "number" || Number.isNaN(att)){
                    att = 0;
                }
                this.currentURLRound = Math.min(this.currentURLRound, att);
                this.requestsFound[key] = Object.assign(new FoundRequest(), req);
                if (!this.requestsFound[key].hasOwnProperty("attempts") || typeof this.requestsFound[key]["attempts"] !== "number"){
                    this.requestsFound[key]["attempts"] = att;
                }
                if (!this.requestsFound[key].hasOwnProperty("processed") || typeof this.requestsFound[key]["processed"] !== "number"){
                    this.requestsFound[key]["processed"] = 0;
                }
                if (preview || printed < previewLimit){
                    console.log(this.requestsFound[key].toString());
                    printed++;
                }
                //this.requestsFound[key]["attempts"] = req["attempts"];
            }
            if (!preview && keys.length > previewLimit){
                console.log(`[WC][DEBUG] loadReqsFromJSON: preview printed first ${previewLimit} only`);
            }

            let seedKeys = Object.keys(tempSeed);
            this.seedRequestsFound = {};
            for (let key of seedKeys){
                let req = tempSeed[key];
                this.seedRequestsFound[key] = Object.assign(new FoundRequest(), req);
                if (!this.seedRequestsFound[key].hasOwnProperty("attempts") || typeof this.seedRequestsFound[key]["attempts"] !== "number"){
                    this.seedRequestsFound[key]["attempts"] = 0;
                }
                if (!this.seedRequestsFound[key].hasOwnProperty("processed") || typeof this.seedRequestsFound[key]["processed"] !== "number"){
                    this.seedRequestsFound[key]["processed"] = 0;
                }
            }
            
            return true
            //console.log(requestsFound);
        }
        console.log("***************** No saved data found **************************");
        return false;

    }

    setIgnoreValues(exclusions){
        if (isDefined(exclusions)){
            this.ignoreValues = new Set(exclusions);
        } else {
            this.ignoreValues = new Set();
        }
    }

    setUrlUniqueIfValueUnique(inclusions){
        if (isDefined(inclusions)){
            this.urlUniqueIfValueUnique = new Set(inclusions);
        } else {
            this.urlUniqueIfValueUnique = new Set();
        }
    }

    resetRequestsAttempts(key){
        console.log(`Trying to reset for ${key}`);
        this.requestsFound[key]["attempts"] = this.currentURLRound - 1;
        console.log(`RESET attempts to ${this.requestsFound[key]["attempts"]} for ${key}`)
    }

    getRequestInfo(){
        let outstr = "";
        for (let key in this.requestsFound){
            let value = this.requestsFound[key];
            outstr += `\x1b[38;5;28m${value.url()}, \x1b[38;5;11m${value.attempts}\x1b[0m\n`
        }
        for (let key in this.seedRequestsFound){
            let value = this.seedRequestsFound[key];
            outstr += `\x1b[38;5;28m${value.url()}, \x1b[38;5;11m${value.attempts}\x1b[0m\n`
        }
        return outstr;
    }

    usingFuzzingDir(){
        this.usingFuzzingDir = true;
    }

    fuzzyValueMatch(soughtValue, testValues){
        let fuzset = fuzzySet([...testValues]);
        let results = fuzset.get(soughtValue,false, this.minFuzzyScore);
        if (results === false){
            return false;
        } else {
            //console.log("Fuzzy Match = ", results[0][0]);
            return true;
        }
    }

    /**
     * Looks for an equivalnt match where fullMatchEquiv of the params or more match one another in the query strings.
     * @param soughtParams
     * @param testParams
     * @param fullMatchEquiv the percent of key/values in the query string that are equivalent to an exact match
     * @returns {boolean}
     */
    equivParameters(soughtParams, testParams, fullMatchEquiv){
        // if target has no query params
        if (testParams.length === 0){
            return false;
        }
        let paramValueMatchCnt=0;
        let gremlinValues = this.gremlinValues;
        // excluded
        //0.3533549273542278&_=1617038119579
        //0.8389814703576484&_=1617038119586
        //0.5336236531483045
        let timeVarRegex = /[0-9.]+[0-9]{6,50}/; // e.g., 0.3533549273542278
        // All keys must be the same for a match
        for (let [skey,svalues] of Object.entries(soughtParams)){
            // add as a match when a variable matches the format for timestamp nanoseconds
            // this might be too lax, should maybe find match for both
            if (timeVarRegex.exec(skey)){
                paramValueMatchCnt++;
                continue;
            }
            if (skey in testParams){
                if (this.ignoreValues.has(skey)){
                    paramValueMatchCnt++;
                } else {
                    //console.log(`svalues=`,svalues, `testParams[skey]=`,testParams[skey], skey, )
                    for (const svalue of svalues.values()){
                        if (testParams[skey].has(svalue) ) {
                            paramValueMatchCnt++;
                            break;
                        } else if (gremlinValues.has(svalue) ||svalue.match(/1999.12.12/) || svalue.match(/12.12.1999/)){
                            paramValueMatchCnt++;
                            break;
                        } else {
                            if (this.urlUniqueIfValueUnique.has(skey)){
                                return false;
                            }
                            if (svalue.length > 5 && this.fuzzyValueMatch(svalue, testParams[skey])){
                                paramValueMatchCnt++;
                                break;
                            }
                        }
                    }
                }
            // } else {
            //     return false;
            }
        }
        //console.log(`Equiv found ${paramValueMatchCnt} of ${fullMatchEquiv} ${(paramValueMatchCnt >= fullMatchEquiv)}`);
        return (paramValueMatchCnt >= fullMatchEquiv);

    }


    keyMatch(soughtParams, testParams){

        if (Object.keys(soughtParams).length !== Object.keys(testParams).length){
            return false;
        }

        for (let param of Object.keys(soughtParams)){
            // want to disable keyMatch equivalence when the key value is required
            if (this.urlUniqueIfValueUnique.has(param)){
                return false;
            }
            if (!(param in testParams)){
                return false;
            }
        }

        return true;
    }

    /**
     * Search the requestData to determine whether a sufficient match exists between urls.
     * An equivalent querystring matches for 100% of the keys and 75% of the values.
     * @param soughtRequest {FoundRequest} - the Request object that contains the query string in question
     * @param forceMatch {boolean} - whether a fuzzy match at the class's rate is used
     * @returns {boolean}
     */
    containsEquivURL(soughtRequest, forceMatch=false){

        let soughtURL = new URL(soughtRequest.url());
        let queryString = soughtURL.search.substring(1);
        let postData = soughtRequest.postData();
        let soughtParamsArr = soughtRequest.getAllParams();
        // let trimmedSoughtParams = [];
        // for (let sp of )
        //soughtParamsArr = [...new Set(soughtParamsArr)];
        let nbrParams = Object.keys(soughtParamsArr).length;
        // if nbrParams*matchPercent is more than nbrParams-1, it's requires a 100% parameter match
        let fullMatchEquiv = nbrParams * this.fuzzyMatchEquivPercent;
        
        let soughtPathname = soughtRequest.getPathname();

        let keyMatch = 0;

        for (let key in this.requestsFound){
            let savedReq = this.requestsFound[key];
            let prevURL = savedReq.getURL();
            let prevPathname = savedReq.getPathname();

            if (prevURL.href === soughtURL.href && savedReq.postData === soughtRequest.postData() && savedReq.hash === soughtURL.hash){
                return true;
            }
            if (forceMatch){
                return false;
            }
            if (prevPathname === soughtPathname && (!soughtURL.hash || savedReq.hash === soughtURL.hash)){

                if (postData.startsWith("<?xml")){
                    let testPostData = savedReq.postData();
                    let re = new RegExp(/<soap:Body>(.*)<\/soap:Body>/);
                    if (re.test(postData) && re.test(testPostData)){
                        let pd_match = re.exec(postData)
                        let test_pd_match = re.exec(testPostData);

                        let matchVal = this.fuzzyValueMatch(pd_match[1], test_pd_match[1])
                        return matchVal;
                    }
                }

                let testParamsArr = savedReq.getAllParams();

                if (this.equivParameters(soughtParamsArr, testParamsArr , fullMatchEquiv)){
                    return true;
                } else if ((nbrParams-1) < fullMatchEquiv){
                    // for situations where the reduced number of parameters forces 100%, also do a keyMatch
                    if (this.keyMatch(soughtParamsArr, testParamsArr) &&  this.fuzzyMatchEquivPercent < .99){
                        keyMatch++;
                    }
                }
            } else {
                // if (savedReq.hash !== soughtURL.hash){
                //     console.log(`Pathnames => ${prevPathname} == ${soughtPathname} hashes=> ${savedReq.hash}\n${soughtURL.hash}`)
                // } else {
                //     console.log(`Pathnames => ${prevPathname} == ${soughtPathname}`)
                // }
            }
        }
        /*since the */
        return (nbrParams <= 3 && keyMatch >= this.maxKeyMatches);
    }

    getValidURL(urlstr, parenturl) {
        let lowerus = urlstr.toLowerCase();
        if (lowerus.startsWith("javascript")) {
            return "";
        }
        try{
            if (lowerus.startsWith("http")) {
                if (lowerus.startsWith(parenturl.origin)) {
                    return urlstr;
                }
                return "";
            }
            return (new URL(urlstr, parenturl.href)).href;
        } catch(ex){
            return "";
        }

    }

    addValidURLS(links, parenturl, origin){
        let requestsAdded = 0;
        for (let link of links){
            let validURLStr = this.getValidURL(link, parenturl);

            if (validURLStr.length > 0){
                let foundRequest = FoundRequest.requestParamFactory(validURLStr, "GET", "",{},origin,this.site_url.href);

                if (!this.containsEquivURL(foundRequest)){
                    foundRequest.from = origin;
                    let addResult = this.addRequest(foundRequest);
                    if (addResult){
                        requestsAdded++;
                        console.log(`[${GREEN}WC${ENDCOLOR}] ${GREEN} ADDED ${ENDCOLOR}${foundRequest.toString()} `);
                    }
                }
            }
        }
        return requestsAdded;
    }

    interestingURL(url) {
        if (url.pathname.endsWith(".php") || url.pathname.search(/php\?/) > -1) {
            return true;
        } else if (url.pathname.endsWith(".css")){
            return false
        }
        return false;

    }

    /**
     *
     * @param foundRequest {FoundRequest}
     * @returns {number}
     */
    addInterestingRequest(foundRequest){
        let requestsAdded =0 ;
        let tempURL = foundRequest.url();
        let urlForExt = tempURL;
        let qidx = urlForExt.indexOf("?");
        if (qidx > -1){
            urlForExt = urlForExt.slice(0, qidx);
        }
        let hidx = urlForExt.indexOf("#");
        if (hidx > -1){
            urlForExt = urlForExt.slice(0, hidx);
        }
        if (urlForExt.endsWith('.css') || urlForExt.endsWith('.jpg') || urlForExt.endsWith('.gif') || urlForExt.endsWith('.png') || urlForExt.endsWith(".js")  || urlForExt.endsWith(".ico")){
            return requestsAdded;
        }
        if (this.containsEquivURL(foundRequest) ) { //|| this.containsMaxNbrSameKeys(tempURL)
            //do nothing for now
            //console.log("[WC] Could have been added, ",req.url(), req.method(), req.postData());
        } else {

            let wasAdded = this.addRequest(foundRequest);
            if (wasAdded){
                let postlen ="";
                if (isDefined(foundRequest.postData())){
                    postlen = foundRequest.postData().length
                }
                requestsAdded++;
                console.log(`[${GREEN}WC${ENDCOLOR}] ${GREEN} ADDED ${ENDCOLOR}-- ${foundRequest.toString()} ${ENDCOLOR}`);
            }
        }
        return requestsAdded;
    }
    nextRequestId(){
        return this.reqCount + this.seedCount + 1;
    }

    //addRequest(urlstr, method, postData, headers, from="interceptedRequest", cookieData="") {
    /**
     * Adds the supplied request to the list of requests
     * @param fRequest:FoundRequest
     * @returns {boolean}
     */
    addRequest(fRequest) {

        // let requestInfo = {
        //     id: this.nextRequestId(), url:urlstr, method: method, postData: postData,
        //     attempts:0, from:from, cookieData:cookieData,
        //     usedFuzzingDir: this.usingFuzzingDir,
        //     content_type: content_type,
        //     processed:0
        // };
        //console.log(requestInfo);
        let reqkey = fRequest.getRequestKey();

        if (reqkey in this.requestsFound) {
            return false;
        } else {
            if (reqkey in this.seedRequestsFound){
                delete this.seedRequestsFound[reqkey];
            }
            fRequest.setId(this.nextRequestId());
            this.collectedURL += 1;
            this.requestsFound[fRequest.getRequestKey()] = fRequest;
            return true;
        }

    }

    addSeedRequest(fRequest) {
        let reqkey = fRequest.getRequestKey();
        if (reqkey in this.requestsFound || reqkey in this.seedRequestsFound) {
            return false;
        } else {
            fRequest.setId(this.nextRequestId());
            this.seedRequestsFound[fRequest.getRequestKey()] = fRequest;
            return true;
        }
    }

    addQueryParam(key, value){
        var keycnt = 0;

        this.inputSet.forEach(function(setkey){
            if (setkey.startsWith(key+"=")){
                keycnt++;
            }
        });
        if (keycnt < 4){
            if (value.search(/[Q2][Q2]+/) > -1){
                value = value.substring(0,1);
            }
            if (this.inputSet.has(`${key}=`) && value.length > 0){
                this.inputSet.delete(`${key}=`);
            }
            if (value.length ===0 && keycnt ===0 || value.length > 0){
                this.inputSet.add(`${key}=${value}`);
            }
        }

    }
    numInputsFound(){
        return this.inputSet.size;
    }
    get reqCount() {
        let count = 0;
        for (let k in this.requestsFound) count++;
        return count;
    }

    get seedCount() {
        let count = 0;
        for (let k in this.seedRequestsFound) count++;
        return count;
    }

    hasRequests(){
        return this.reqCount === 0;
    }
    numRequestsFound(){
        return this.reqCount + this.seedCount;
    }
    ignoreRequest(urlstr){
        try {
            let url = new URL(urlstr);
            if (url.pathname.endsWith('logout.php')){
                return true;
            }
            
        } catch (ex){
            console.log(`ERROR converting ${urlstr} to URL `);
            console.log(ex);
        }
        return false;
    }
    shuffle(array) {
        let currentIndex = array.length,  randomIndex;
        
        // While there remain elements to shuffle...
        while (currentIndex !== 0) {
            
            // Pick a remaining element...
            randomIndex = Math.floor(Math.random() * currentIndex);
            currentIndex--;
            
            // And swap it with the current element.
            [array[currentIndex], array[randomIndex]] = [
                array[randomIndex], array[currentIndex]];
        }
        
        return array;
    }
    
    // return True if the pathname of one to investigate matches current, gives more diversity when a bunch of a single type exist.
    checkToSkip(new_urlstr){
        try {
            if (!this.currentRequest){
                return false;
            }
            let cur_urlstr = this.currentRequest._urlstr;
            let new_url = new URL(new_urlstr);
            let cur_url = new URL(cur_urlstr);
            if (new_url.pathname === cur_url.pathname){
                return true;
            }
        
        } catch (ex){
            console.log(`ERROR converting ${new_urlstr} or ${cur_urlstr} to URL in checkToSkip`);
            console.log(ex);
        }
        return false
    }
    getNextRequest() {
        let skips = 0;
        // console.log(inputSet);
        while (this.currentURLRound <= MAX_NUM_ROUNDS || this.seedURLRound <= MAX_NUM_ROUNDS) {
            let mainExhausted = this.currentURLRound > MAX_NUM_ROUNDS;
            let seedExhausted = this.seedURLRound > MAX_NUM_ROUNDS;

            let primary = (this._timeSliceIndex < MAIN_SLICE_QUOTA) ? "main" : "seed";
            let secondary = primary === "main" ? "seed" : "main";

            let picked = null;
            if (primary === "main" && !mainExhausted){
                picked = this._getNextFromStore(this.requestsFound, "main");
            } else if (primary === "seed" && !seedExhausted){
                picked = this._getNextFromStore(this.seedRequestsFound, "seed");
            }
            if (!picked){
                if (secondary === "main" && !mainExhausted){
                    picked = this._getNextFromStore(this.requestsFound, "main");
                } else if (secondary === "seed" && !seedExhausted){
                    picked = this._getNextFromStore(this.seedRequestsFound, "seed");
                }
            }
            if (picked){
                this._timeSliceIndex = (this._timeSliceIndex + 1) % TOTAL_SLICE_QUOTA;
                return picked;
            }
            if (this.currentURLRound > MAX_NUM_ROUNDS && this.seedURLRound > MAX_NUM_ROUNDS){
                break;
            }
        }
        return null;
    }

    _getNextFromStore(store, storeName){
        while (true){
            let roundValue = (storeName === "seed") ? this.seedURLRound : this.currentURLRound;
            if (roundValue > MAX_NUM_ROUNDS){
                return null;
            }
            let cnt = 0;
            for (let key in store) {
                let req = store[key];
                cnt++;
                if (this.ignoreRequest(req._urlstr)){
                    //console.log(`IGNORING >>>>> ${key} `);
                    store[key]["attempts"] = MAX_NUM_ROUNDS
                } else {
                    if (req["attempts"] < roundValue) {
                        // We skip 'checkToSkip' logic if there's no randomKeys.length equivalent,
                        // or we could track size. Actually, this checkToSkip logic used (cnt+5) < randomKeys.length
                        if (storeName === "main" && (cnt+5) < this.reqCount && this.checkToSkip(req["_urlstr"])){
                            continue;
                        }
                        req["attempts"] += 1;
                        this.save();
                        req["key"] = key;
                        this.currentRequest = req;
                        return req;
                    }
                }
            }
            if (storeName === "seed"){
                this.seedURLRound += 1;
                console.log("SEED ROUND VALUE HAS INCREASED TO ", this.seedURLRound);
            } else {
                this.currentURLRound += 1;
                console.log("CURRENT ROUND VALUE HAS INCREASED TO ", this.currentURLRound);
            }
        }
    }

    save() {
        //await exerciseTarget(page, new URL(key));
        for (let key in this.requestsFound) {
            let req = this.requestsFound[key];
            if (req["_method"] === "POST"){
                req["response_status"] = 200;
            }
        }
        for (let key in this.seedRequestsFound) {
            let req = this.seedRequestsFound[key];
            if (req["_method"] === "POST"){
                req["response_status"] = 200;
            }
        }

        let meta = this.meta;
        if (!meta || typeof meta !== "object"){
            meta = {init:{}};
        }
        if (!meta.hasOwnProperty("init") || typeof meta.init !== "object"){
            meta.init = {};
        }
        let jdata = JSON.stringify({requestsFound: this.requestsFound, seedRequestsFound: this.seedRequestsFound, inputSet: Array.from(this.inputSet), _witcher_meta: meta});
        fs.writeFileSync(path.join(this.base_appdir, "request_data.json"), jdata);
    }
}

// var inputSet = new Set();
//var formsData = {}; // {<method+url>:{action:"", method:"", elems:{<parameter>:""} }

process.on('uncaughtException', function(err) {
    console.log('Caught exception: ' + err);
    console.log(err.stack);
});


/**
 * Attempts to parse the text, if there's a syntax error then returns false
 * @param response
 * @param responseText
 * @returns {boolean}
 */
export function isInteractivePage(response, responseText){

    try {
        JSON.parse(responseText);
        return false;
    } catch (SyntaxException){
        //check out other types
    }

    if (response.headers().hasOwnProperty("content-type")){

        let contentType = response.headers()['content-type'];

        if (contentType === "application/javascript" || contentType === "text/css" || contentType.startsWith("image/") || contentType === "application/json"){
            console.log(`Content type ${contentType} is considered non-interactive (e.g., JavaScript, CSS, json, or image/* )`)
            return false;
        }
    }

    //console.log(responseText.slice(0,500))
    if (responseText.search(/<body[ >]/) > -1 || responseText.search(/<form[ >]/) > -1 || responseText.search(/<frameset[ >]/) > -1 ){
        return true;
    } else {
        console.log(responseText.slice(0,5000))
        console.log(`[WC]NO HTML tag FOUND anywhere, skipping ${response.url()}`)
        return false;
    }

}

function hasValuable5xxSignals(responseText){
    const text = String(responseText || "");
    const lower = text.toLowerCase();
    const businessIndicators = [
        "sql", "mysql", "query", "select", "insert",
        "warning:", "fatal error", "stack trace",
        "line ", "file ", "/var/www",
        "exception", "backtrace", "debug",
        // extra useful backend/business diagnostics
        "sqlstate", "pdoexception", "database error", "db error",
        "uncaught", "call stack", "traceback", "stacktrace",
        "undefined index", "undefined variable", "notice:",
        "parse error", "syntax error", "permission denied",
        "not found in", "at line", "on line"
    ];
    let hitIndicators = [];
    for (const kw of businessIndicators){
        if (lower.indexOf(kw) > -1){
            hitIndicators.push(kw);
        }
    }
    const hasBusiness = hitIndicators.length > 0;
    const hasHtmlShell = lower.indexOf("<html") > -1 && lower.indexOf("<body") > -1;
    const richHtmlMarkers = ["<form", "<table", "<script", "<main", "<section", "<article", "<nav", "<header", "<footer", "<title"];
    let richCount = 0;
    for (const mk of richHtmlMarkers){
        if (lower.indexOf(mk) > -1){
            richCount += 1;
        }
    }
    const hasStructuredHtml = hasHtmlShell && (richCount >= 3 || lower.length >= 1200);
    return {
        ok: hasBusiness || hasStructuredHtml,
        hasBusiness,
        hasStructuredHtml,
        hitIndicators: hitIndicators.slice(0, 10),
    };
}
function logdata(msg){
    console.log("\x1b[38;5;6m[DATA] ", msg, "\x1b[0m")
}
function isDefined(val) {
    return !(typeof val === 'undefined' || val === null);
}

/**
 *
 *
 *
 *
 */
export class RequestExplorer {

    constructor(appData, workernum, base_appdir, currentRequest ) {
        this.appData= appData;
        this.base_appdir = base_appdir;
        this.loopcnt=0;
        this.cookies = [];
        this.bearer = "";
        this.isLoading = false;
        this.reinitPage= false;
        this.loadedURLs = [];
        this.passwordValue = "";
        this.usernameValue = "";
        if (appData.numRequestsFound() > 0 && currentRequest != null){
            this.currentRequestKey = currentRequest.getRequestKey();
            this.url = currentRequest.getURL();
            this.method = currentRequest.method();
            this.postData = currentRequest.postData()
            this.cookieData = currentRequest.cookieData();


            if (this.appData.requestsFound.hasOwnProperty(this.currentRequestKey))
                this.appData.requestsFound[this.currentRequestKey]["processed"]++;
            else if (this.appData.seedRequestsFound && this.appData.seedRequestsFound.hasOwnProperty(this.currentRequestKey))
                this.appData.seedRequestsFound[this.currentRequestKey]["processed"]++;
            else{
                // this.appData.requestsFound[this.currentRequestKey] = currentRequest;
                // this.appData.requestsFound[this.currentRequestKey]["processed"] = 1;
                console.log(`\x1b[31mWE SHOULD ME ADDING currentRequest to requestsFound ${this.currentRequestKey}\x1b[0m`);
            }
        } else {
            this.currentRequestKey = "GET";
            this.url = "";
            this.method = "GET";
            this.postData = "";
            this.cookieData = "";
        }
        this.requestsAdded = 0;
        this.timeoutLoops = 5;
        this.timeoutValue = 3;
        this.actionLoopTimeout = 45;
        this.workernum = workernum;
        this.gremCounter = {};
        this.shownMessages = {};
        this.maxLevel = 10;
        this.browser;
        this.page;
        this.gremlins_error = false;
        this.lamehord_done = false
        this.abortCurrentRequest = false;
        this.abortPromiseResolver = null;
        this.getConfigData();
        this.gremlins_url = "";
    }

    getConfigData(){
        let json_fn = path.join(this.base_appdir,"witcher_config.json");
        if (fs.existsSync(json_fn)){
            let jstrdata = fs.readFileSync(json_fn);
            this.loginData = JSON.parse(jstrdata)["request_crawler"];
            this.appData.setIgnoreValues(this.loginData["ignoreValues"]);
            this.appData.setUrlUniqueIfValueUnique(this.loginData["urlUniqueIfValueUnique"]);
        }
    }
    hasCompleteLoginSelectors(){
        if (!this.loginData || typeof this.loginData !== "object"){
            return false;
        }
        const usernameSelector = String(this.loginData["usernameSelector"] || "").trim();
        const passwordSelector = String(this.loginData["passwordSelector"] || "").trim();
        return usernameSelector.length > 0 && passwordSelector.length > 0;
    }
    getExtraLoginFields(){
        if (!this.loginData || typeof this.loginData !== "object"){
            return [];
        }
        const extraFields = [];
        for (const key of Object.keys(this.loginData)){
            const match = key.match(/^extraSelector_(\d+)$/);
            if (!match){
                continue;
            }
            const selector = String(this.loginData[key] || "").trim();
            if (selector.length === 0){
                continue;
            }
            const valueKey = `extraValue_${match[1]}`;
            const rawValue = Object.prototype.hasOwnProperty.call(this.loginData, valueKey) ? this.loginData[valueKey] : "";
            let index = parseInt(match[1], 10);
            if (Number.isNaN(index)){
                index = Number.MAX_SAFE_INTEGER;
            }
            extraFields.push({
                index,
                selector,
                value: rawValue == null ? "" : String(rawValue)
            });
        }
        extraFields.sort((a, b) => a.index - b.index);
        return extraFields;
    }
    hasValidLoginFormUrl(){
        if (!this.loginData || typeof this.loginData !== "object"){
            return false;
        }
        const formUrl = String(this.loginData["form_url"] || "").trim();
        if (formUrl.length === 0){
            return false;
        }
        try{
            new URL(formUrl);
            return true;
        } catch(ex){
            return false;
        }
    }
    async page_frame_selection(selector){
        let results = []
        const elementHandles = await page.$$(selector);
        for (let ele of elementHandles) {
            results.push(ele);
        }
        for (const frame of page.mainFrame().childFrames()){
            const frElementHandles = await frame.$$(selector);
            for (let ele of frElementHandles) {
                results.push(ele);
            }
        }
        return results;
    }
    async resetURLBack(page){
        let cururl = await page.url();
        console.log("[WC] cururl = ", typeof(cururl), cururl, cururl.startsWith("chrome-error"),"\n");
        if (cururl.startsWith("chrome-error")){
            await page.goBack();
            let backedurl = await page.url();
            console.log(`[WC] Performed goBack to ${backedurl} after chrome-error`);
        }
    }
    async searchForURLSelector(page, tag, attribute, completed={}){
        let elements = [];
        console.log("[WC] searchForURLSelector starting.");
        try {
            const links = await page.$$(tag);
            for (var i=0; i < links.length; i++) {
                if (links[i]){
                    if (i === 0){
                        let hc_str = "[unknown]";
                    try {
                        let hc = await links[i].getProperty("hashCode");
                        hc_str = hc ? String(hc) : "[null]";
                    } catch (e) {}
                    //console.log(`[WC] check element hash = ${hc_str}`);
                    }
                    await this.resetURLBack(page);
                    let valueHandle = null;
                    try{
                        valueHandle = await links[i].getProperty(attribute);
                    } catch(ex){
                        console.log(`[WC] \x1b[38;5;197m link #${i}/${links.length} error encountered while trying to getProperty`, typeof(page), page.url(), tag, attribute, "\n", (ex && ex.message ? ex.message : String(ex)), "\x1b[0m");
                        try {
                            //console.log("[WC] Trying again", (links[i] ? typeof links[i] : "null"));
                            
                            valueHandle = await links[i].getProperty(attribute);
                        } catch (eex){
                            continue;
                        }
                    }
                    let val = await valueHandle.jsonValue();
                    if (isDefined(val)){
                        elements.push(val);
                    }
                    
                    console.log(`[WC] link #${i}/${links.length} completed`);
                }
            }

        } catch (e){
            let safeErr = e && typeof e.message === 'string' ? e.message : "Unknown Error";
            console.log("[WC] error encountered while trying to search for tag", typeof(page), page.url(), tag, attribute, "\n\t", safeErr);
        }
        return elements;
    }


    async getAttribute(node, attribute, defaultval=""){
        let valueHandle = await node.getProperty(attribute);
        let val = await valueHandle.jsonValue();
        if (isDefined(val)){
            //logdata(attribute + val);
            //elements.push(val);
            return val;
        }
        return defaultval;
    }
    addFormbasedRequest(foundRequest, requestsAdded){
        if (foundRequest.isSaveable() ){ // && this.appData.containsMaxNbrSameKeys(tempurl) === false
        
            if (this.appData.containsEquivURL(foundRequest, true) ) {
                // do nothing yet
                //console.log("[WC] Could have been added, ",foundRequest.postData());
            } else {
                let url = new URL(foundRequest.urlstr());
            
                if (foundRequest.urlstr().startsWith(`${this.appData.site_url.origin}`) || this.appData.ips.includes(url.hostname)){
                    foundRequest.from = "PageForms";
                    foundRequest.cleanURLParamRepeats()
                    foundRequest.cleanPostDataRepeats()
                    let wasAdded = this.appData.addRequest(foundRequest);
                    if (wasAdded){
                        requestsAdded++;
                        if (foundRequest.postData()){
                            let pd_str = foundRequest.postData();
                            if (pd_str.length > 200) {
                                pd_str = pd_str.substring(0, 200) + `... [truncated, total length: ${pd_str.length}]`;
                            }
                            console.log(`[${GREEN}WC${ENDCOLOR}] ${GREEN} ADDED ${ENDCOLOR}${foundRequest.toString()} postData=${pd_str} ${ENDCOLOR}`);
                        } else {
                            console.log(`[${GREEN}WC${ENDCOLOR}]] ${GREEN} ADDED ${ENDCOLOR}${foundRequest.toString()} \n ${ENDCOLOR}`);
                        }
                    }
                } else {
                    console.log(`\x1b[38;5;3m[WC] IGNORED b/c not correct ${foundRequest.toString()} does not start with ${this.appData.site_url.origin} ips = ${this.appData.ips} hostname=${url.hostname} -- ${ENDCOLOR}`);
                }
            }
        }
        return requestsAdded;
    }
    async searchForInputs(node){
        let requestsAdded = 0;
        let requestInfo = {}; //{action:"", method:"", elems:{"attributename":"value"}
        let nodeaction = await this.getAttribute(node, "action");
        let method = await this.getAttribute(node, "method");


        const buttontags = await node.$$('button');
        let formdata = await this.searchTags(buttontags);

        const inputtags = await node.$$('input');
        formdata += await this.searchTags(inputtags);

        const selectags = await node.$$('select');
        formdata += await this.searchTags(selectags);

        const textareatags = await node.$$('textarea');
        formdata += await this.searchTags(textareatags);
        if (formdata.length === 0){
            return requestsAdded;
        }
        
        let formInfo = FoundRequest.requestParamFactory(nodeaction, method, "",{},"PageForms",this.appData.site_url.href);
        formInfo.addParams(formdata);
        let allParams = formInfo.getAllParams();
        
        let basedata = "";
        for (let pkey in allParams) {
            let pvalue = allParams[pkey];
            if (formInfo.multipleParamKeys.has(pkey)) {
                continue;
            }
            let arrVal = Array.from(pvalue);
            if (arrVal.length > 0){
                basedata += `${pkey}=${arrVal[0]}&`
            } else {
                basedata += `${pkey}=&`
            }
        }
        
        // Prevent OOM from excessively long forms
        if (basedata.length > 5000) {
            console.log(`[WC] Warning: Form base data is too long (${basedata.length} bytes). Truncating to prevent memory exhaustion and state explosion.`);
            // Only take the first 5000 characters of form fields, making sure we don't break in the middle of a key
            let truncated = basedata.substring(0, 5000);
            let lastAmp = truncated.lastIndexOf('&');
            if (lastAmp > 0) {
                basedata = truncated.substring(0, lastAmp + 1);
            }
        }

        let postdata = [basedata]
        
        // Limit permutations to prevent combinatorial explosion which leads to OOM
        let maxPermutations = 50;
        let currentPermutations = 1;

        for (let mpk of formInfo.multipleParamKeys) {
            let new_pd = []
            let values = Array.from(allParams[mpk]);
            
            // Limit values per multiple param key
            if (values.length > 5) {
                values = values.slice(0, 5);
            }

            for (let ele of values){
                for (let pd of postdata){
                    if (currentPermutations * values.length > maxPermutations) {
                        break;
                    }
                    new_pd.push(pd + `${mpk}=${ele}&`);
                }
            }
            if (new_pd.length > 0) {
                postdata = new_pd;
                currentPermutations = postdata.length;
            }
        }
        
        for (let pd of postdata){
            let formBasedRequest = FoundRequest.requestParamFactory(nodeaction, method, pd,{},"PageForms",this.appData.site_url.href);
            //console.log("[WC] Considering the addition of ",typeof(formBasedRequest.urlstr()), formBasedRequest.urlstr(), formBasedRequest.postData());
            requestsAdded = this.addFormbasedRequest(formBasedRequest, requestsAdded);
        }
        
        return requestsAdded;
    }

    async searchTags(tags) {
        let formdata = "";
        for (let j = 0; j < tags.length; j++) {
            let tagname = encodeURIComponent(await this.getAttribute(tags[j], "name"));
            let tagval = encodeURIComponent(await this.getAttribute(tags[j], "value"));
            formdata += `${tagname}=${tagval}&`;
            this.appData.addQueryParam(tagname, tagval);
        }
        return formdata;
    }

    async addURLsFromPage(page, parenturl){
        let requestsAdded = 0;
        try {
            // these are always GETs
            const anchorlinks = await this.searchForURLSelector(page, 'a', 'href');
            if (anchorlinks){
                //console.log("[WC] adding valid URLS from anchors ")
                requestsAdded += this.appData.addValidURLS(anchorlinks, parenturl, "OnPageAnchor");
            }
            const iframelinks = await this.searchForURLSelector(page, 'iframe', 'src');
            if (iframelinks){
                //console.log("[WC] adding valid URLS from iframe links")
                requestsAdded += this.appData.addValidURLS(iframelinks, parenturl, "OnPageIFrame");
            }
        } catch (ex){
            console.log(`[WC] Error in addURLSFromPage(): ${ex}`)
        }
        return requestsAdded;
    }

    async addFormData(page) {
        let requestsAdded = 0;
        try{
            const forms = await page.$$('form').catch(reason => {
                console.log(`received error in page. ${reason} `);
            });
            if (isDefined(forms)){
                for (let i = 0; i < forms.length; i++) {
                    let faction = await this.getAttribute(forms[i], "action", "");
                    let fmethod = await this.getAttribute(forms[i], "method", "GET");
                    console.log("[WC] second form ACTION=", faction, fmethod, " FROM url ", await page.url());
                    requestsAdded += await this.searchForInputs(forms[i]);
                }
            }

        } catch (ex){
            console.log(`[WC] addFormData(p) Error ${ex}`);
            console.log(ex.stack);
        }
        return requestsAdded;
    }

    async addDataFromBrowser(page, parenturl){
//        console.log("Starting formdatafrompage");
        let requestsAdded = 0;
        let childFrames = this.page.mainFrame().childFrames();

        if (typeof childFrames !== 'undefined' && childFrames.length > 0){
            for (const frame of childFrames ){
                //console.log("[WC] Attempting to ADD form data from FRAMES. "); //, await frame.$$('form'))
                if (frame.isDetached()){
                    console.log("\x1b[31mDETACHED FRAME \x1b[0m", frame.url());
                    await this.page.reload();
                }
                requestsAdded += await this.addFormData(frame);
                requestsAdded += await this.addURLsFromPage(frame, parenturl);
            }
        }
        requestsAdded += await this.addFormData(page);
        requestsAdded += await this.addURLsFromPage(page, parenturl);
        
        //const bodynode = await page.$('html');
        //requestsAdded += await this.searchForInputs(bodynode);
        return requestsAdded;
    }


    async addCodeExercisersToPage(gremlinsHaveStarted, usernameValue="", passwordValue=""){
        // ##############################################################################
        //                         START Injected Exercise Code
        // ##############################################################################

        await this.page.evaluate((gremlinsHaveStarted, usernameValue, passwordValue)=>{
            window.gremlinsHaveFinished = false
            window.gremlinsHaveStarted = gremlinsHaveStarted;
            /***************************************************************************************************************************************************************************************
             ***************************************************************************************************************************************************************************************
             ***************************************************************************************************************************************************************************************
             *
             *
             * TODO:REMOVE ME!!!!
             *
             *
             ***************************************************************************************************************************************************************************************
             ***************************************************************************************************************************************************************************************/
            gremlinsHaveStarted = true;
            
            var formEntries = {}
            // taken from https://superuser.com/questions/455863/how-can-i-disable-javascript-popups-alerts-in-chrome
            // ==UserScript==
            // @name        Wordswithfriends, Block javascript alerts
            // @match       http://wordswithfriends.net/*
            // @run-at      document-start
            // ==/UserScript==
    
    
            function overrideSelectNativeJS_Functions () {
                console.log("[WC] ---------------- OVERRIDING window.alert ------------------------------");
                window.alert = function alert (message) {
                    console.log (message);
                }
            }
    
            function addJS_Node (text, s_URL, funcToRun) {
                var D                                   = document;
                var scriptNode                          = D.createElement ('script');
                scriptNode.type                         = "text/javascript";
                if (text)       scriptNode.textContent  = text;
                if (s_URL)      scriptNode.src          = s_URL;
                if (funcToRun)  scriptNode.textContent  = '(' + funcToRun.toString() + ')()';
        
                var targ = D.getElementsByTagName ('head')[0] || D.body || D.documentElement;
                console.log(`[WC] Alert OVERRIDE attaching script to ${targ}`);
                targ.appendChild (scriptNode);
            }
            
            addJS_Node (null, null, overrideSelectNativeJS_Functions);
            if (usernameValue === ""){
                usernameValue = "Witcher";
            }
            if (passwordValue === ""){
                passwordValue = "Witcher";
            }
            console.log(`[WC] usernameValue = ${usernameValue} passwordValue = ${passwordValue}`);
            const CLICK_ELE_SELECTOR = "div,li,span,input,p,button";
            //const CLICK_ELE_SELECTOR = "button";
            var usedText = new Set();
            const STARTPAGE = window.location.href;
            const MAX_LEVEL = 10;
            
            let today = new Date();
            let dd = String(today.getDate()).padStart(2, '0');
            let mm = String(today.getMonth() + 1).padStart(2, '0'); //January is 0!
            let yyyy = today.getFullYear();
            
            var currentDateYearFirst = `${yyyy}-${mm}-${dd}`;
            var currentDateMonthFirst = `${mm}-${dd}-${yyyy}`;
            
            function shuffle(array) {
                var currentIndex = array.length, temporaryValue, randomIndex;

                // While there remain elements to shuffle...
                while (0 !== currentIndex) {

                    // Pick a remaining element...
                    randomIndex = Math.floor(Math.random() * currentIndex);
                    currentIndex -= 1;

                    // And swap it with the current element.
                    temporaryValue = array[currentIndex];
                    array[currentIndex] = array[randomIndex];
                    array[randomIndex] = temporaryValue;
                }

                return array;
            }
            function sleep(ms) {
                return new Promise(resolve => setTimeout(resolve, ms));
            }
            function getChangedDOM(domBefore, domAfter){
                let changedDOM = [];
                for (let i = 0; i < domBefore.length; i++){
                    let db = domBefore[i];
                    let found = false;
                    for (let j = 0; j < domAfter.length; j++){
                        if (db === domAfter[j]){
                            found = true;
                            break;
                        }
                    }
                    if (!found){
                        changedDOM.push(db);
                    }
                }
                // if domAfter larger, then add entries if not in domBefore
                for (let daIndex = domBefore.length; daIndex < domAfter.length; daIndex++){
                    let da = domAfter[daIndex];
                    let found = false;
                    for (let j = 0; j < domBefore.length; j++){
                        if (domBefore[j] === da){
                            found = true;
                            break;
                        }
                    }
                    if (!found){
                        changedDOM.push(da);
                    }
                }
                return changedDOM;
            }
            function indent(cnt){
                let out = ""
                for (let x =0;x<cnt;x++){
                    out += "  ";
                }
                return out;
            }
            async function clickSpam(elements, level=0, parentClicks=[]){
                if (level >= MAX_LEVEL){
                    console.log(`[WC] ${indent(level)} L${level} too high, skipping`);
                    return;
                }
                //let randomArr = shuffle(Array.from(elements));
                let randomArr = Array.from(elements);
                //console.log(`[WC] ${indent(level)} L${level} Starting cliky for ${randomArr.length} elements`);
                //t randomArr = Array.from(Object.values(elements));

                let mouseEvents = ["click","mousedown","mouseup"];
                let eleIndex = 0;
                let startingURL = location.href;
                let startingDOM = document.querySelectorAll(CLICK_ELE_SELECTOR);
                var frames = window.frames; // or // var frames = window.parent.frames;
                let frameurls = []
                if (frames){
                    for (let i = 0; i < frames.length; i++) {
                        startingDOM = [... startingDOM, ...frames[i].document.querySelectorAll(CLICK_ELE_SELECTOR)];
                        frameurls.push(frames[i].location)
                    }
                    
                    //console.log(`[WC] ${indent(level)} L${level} FOUND StartingDOM ${startingDOM.length} elements to use with curDOM not sure why not using ${elements.length}`);
                }
                //console.log(`[WC] ${indent(level)} L${level} Starting DOM selected=${startingDOM.length} Nodes toExplore=${randomArr.length} `);
                //console.log(`[WC] ${indent(level)} L${level} number of elements initially `, startingDOM.length);
                // startingDOM.filter(function (e) {
                //     return e.hasOwnProperty("hasClicker");
                // });
                function check_for_url_change_in_frames(frameurls) {
                    let framediff = false;
                    
                    if (frames) {
                        for (let i = 0; i < frames.length; i++) {
                            if (frames[i].location !== frameurls[i]) {
                                framediff = true;
                                break;
                            }
                        }
                    }
                    return framediff;
                    
                }
                function report_frame_changes(frameurls) {
                    
                    if (frames) {
                        for (let i = 0; i < frames.length; i++) {
                            if (frames[i].location !== frameurls[i]) {
                                console.log(`[WC] FOUND a change to frame ${i}`, frames[i].location.href);
                                console.log(`[WC-URL] ${frames[i].location}` ); // report changed location to puppeteer
                            }
                        }
                    }
                    
                }

                for (let eleIndex =0; eleIndex < randomArr.length; eleIndex++){
                    let ele = randomArr[eleIndex];
                    let textout = ele.textContent.replaceAll("\n",",").replaceAll("  ", "")
                    
                    //console.log(`[WC] ${indent(level)} L${level} attempt to click on e#${eleIndex} of ${randomArr.length} : ${textout.length} ${textout.substring(0,50)}`);
                    try {
                        if (ele.href != null){
                            console.log(`${indent(level)} L${level} FOUND URL of ${ele.href}`)
                            if (ele.href.indexOf("support.dlink.com") !== -1){
                                console.log(`[WC] IGNORING url of FOUND URL of ${ele.href}`)
                                continue;
                            }
                        }
                        let searchText="";
                        if (ele.outerHTML != null) {
                            searchText += ele.outerHTML;
                        }
                        if (ele.innerHTML != null) {
                            searchText += ele.innerHTML;
                        }
                        if (ele.textContent != null) {
                            searchText += ele.textContent;
                        }
                        //console.log(`ele id=${ele.id} name=${ele.name}`)
                        if (usedText.has(ele.innerHTML) ){
                            //console.log("[WC] SKIPPING B/C IT'found in usedText, ");
                            continue;
                            //return;  // not sure why it was a return that's causing it to exit the entire thing
                        }
                        let pos = searchText.indexOf("Logout");
                        if (pos > -1 ){
                            console.log("[WC] SKIPPING B/C IT's a logout, ", ele.textContent);
                            continue;
                        }

                        try {
                            ele.disabled = false;
                        } catch (ex){
                            //pass
                            let safeErr = ex && typeof ex.message === 'string' ? ex.message : "Unknown Error";
                            console.log("[WC] ERROR WITH THE ELEMENTS CLICKING : ", safeErr);
                        }

                        try {

                            function triggerMouseEvent (node, eventType) {
                                //console.log("usedText=", usedText, "node=", node);
                                // if
                                // if (node.textContent.indexOf("Order History") === -1 && node.textContent.indexOf("account_circle") === -1 && node.textContent.indexOf("check_circle_outline") === -1 ){
                                //     return;
                                // }
                                if (level > 1){
                                    console.log(`[WC] ${indent(level)} L${level} ${indent(level)} L${level} triggering on ${node.textContent}`)
                                }
                                //console.log("usedText=", usedText, "node=", node);
                                // if (usedText.has(node.textContent) ){
                                //     return;
                                // }

                                usedText.add(node.innerHTML);
                                let clickEvent = document.createEvent ('MouseEvents');
                                clickEvent.initEvent (eventType, true, true);
                                node.dispatchEvent (clickEvent);
                                if(typeof node.click === 'function') {
                                    try{
                                        node.click()
                                        // if (node.textContent){
                                        //     console.log(`[WC] ${indent(level)} L${level} Fired clicky poo -- ${node.nodeType} ${node.textContent.substring(0,20)} ${eventType}`);
                                        // } else {
                                        //     console.log(`[WC] ${indent(level)} L${level} Fired clicky poo `);
                                        // }
                                    } catch (ex){
                                        console.log(`[WC] ${indent(level)} L${level} click method threw an error ${ex}`);
                                    }
                                }
                                //console.log(`[WC] ${indent(level)} L${level} DONE-TRIGGERED triggering on`, clickEvent, node, node.id, node.name, node.click);
                            }
                            
                            for (let ev of mouseEvents){
                                //console.log("mouse event = ", ev);
                                let mainurl = window.location.href;
                                let hiddenChildren = [];
                                for (clickablechild of startingDOM) {
                                    if (clickablechild.offsetParent === null){
                                        hiddenChildren.push(clickablechild)
                                    }
                                }
                                
                                //console.log(`[WC] ${indent(level)} L${level} HIDDEN CHILDREN at start = ${hiddenChildren.length}`)
                                
                                triggerMouseEvent (ele, ev);
                                
                                await sleep(50);
                                
                                let mainurl_changed = mainurl !== window.location.href
                                if (mainurl_changed || check_for_url_change_in_frames(frameurls)){
                                    // bubble up URL for change
                                    if (mainurl_changed){
                                        console.log(`[WC] ${indent(level)} L${level} FOUND a change to main frame `, mainurl, window.location.href);
                                        console.log(`[WC-URL]${window.location.href}`);
                                    } else {
                                        report_frame_changes(frameurls)
                                    }
                                    // reload main frame
                                    await window.location.replace(main);
                                    // retrigger parents after reload to show the children
                                    for (let pc of parentClicks) {
                                        //console.log (`[WC] ${indent(level)} retriggering ${pc.textContent}`);
                                        triggerMouseEvent(pc, "click");
                                    }
                                }
                                
                                let curDOM = document.querySelectorAll(CLICK_ELE_SELECTOR);
                                if (frames) {
                                    for (let i = 0; i < frames.length; i++) {
                                        curDOM = [... curDOM, ...frames[i].document.querySelectorAll(CLICK_ELE_SELECTOR)];
                                    }
                                    //console.log(`[WC] ${indent(level)} L${level} FOUND ${curDOM.length}  curkeys=${Object.keys(curDOM).length} startkey=${Object.keys(startingDOM).length} `);
                                }
                                let newlyVisibleLinks = []
                                for (child of hiddenChildren){
                                    if (child.offsetParent !== null){
                                        try{
                                            let newvislinks = ""
                                            for (let subc of child.querySelectorAll(CLICK_ELE_SELECTOR)){
                                                if (subc.offsetParent === null){
                                                    newvislinks += subc.textContent + ", ";
                                                }
                                            }
                                            if (nawvislink.length === 0 ){
                                                newvislinks = child.textContent.replace("\n",",").replace(" ","");
                                            }
                                            console.log(`[WC] ${indent(level)} L${level} after clicking on ${ele.textContent} adding newly visible link ${newvislinks} `);
                                            
                                        } catch (eex){
                                            console.log("[WC] Error with finding newly visible link ", eex.stack);
                                        }
                                        newlyVisibleLinks.push(child);
                                    }
                                }
                                if (newlyVisibleLinks.length > 0){
                                    console.log(`[WC] ${indent(level)} L${level} click on ${ele.textContent} showed ${newlyVisibleLinks.length} new links, recursing the new links`);
                                    parentClicks.push(ele);
                                    await clickSpam(newlyVisibleLinks, level+1, parentClicks)
                                }
                                
                                // have we added any clickable items that we need to now clicky?
                                if (curDOM.length !== startingDOM.length && curDOM.length > 0){
                                    console.log(`[WC] maybe some difference here`)
                                    var changedDOM = getChangedDOM(startingDOM, curDOM);
                                    console.log(`[WC] ${indent(level)} ${level} starting len = ${elements.length} cur len = ${curDOM.length} changed len=${changedDOM.length}`);
                                    /*for (let cd = 0; cd < changedDOM.length; cd++){
                                        console.log(`[WC] ${indent(level+1)} changedDOM #${cd} ${changedDOM[cd].textContent}`);
                                    }*/
                                    parentClicks.push(ele);
                                    console.log(`[WC] ${indent(level)} L${level} recursing into the next level of ${ele.textContent}`);
                                    await clickSpam(changedDOM, level+1, parentClicks);
                                    // this resets DOM??
                                    location.href = startingURL;
                                    //startingDOM = document.querySelectorAll("div,li,span,a,input,p,button");

                                    // can break by assuming that DOM change means event was heard.
                                    break;
                                } else {
                                    //console.log(`[WC] ${indent(level)} ${level} ${Object.keys(startingDOM).length} ${Object.keys(curDOM).length}`)
                                }

                            }
                            await sleep(50);


                        } catch(e2){
                            console.trace("[WC] NO CLICK, ERROR ", e2.message);
                            if (e2.stack){
                                console.log("[WC] ", e2.stack);
                            } else {
                                console.log("[WC] Stack is unavailable to print");
                            }

                        }

                        // if (typeof ele.click === 'function') {
                        //
                        //     console.log("\tLOG gremlin click all_clicker ", cnt );
                        //     console.log("\tLOG gremlin click all_clicker ", cnt );
                        //     //ele.click();
                        //     //await sleep(100);
                        // } else {
                        //     console.log("\tNO CLICK ");
                        // }

                    } catch (e){
                        console.trace("[WC] ERROR WITH THE ELEMENTS CLICKING ", e.message);
                        if (e.stack){
                            console.log("[WC] ", e.stack);
                        } else {
                            console.log("[WC] Stack is unavailable to print");
                        }
                    }

                } //end for loop eleIndex
            }


            async function checkHordeLoad(){
                if (typeof window.gremlins === 'undefined') {
                    console.log("cannot find gremlins, attempting to load on the fly");
                    (function (d, script) {
                        script = d.createElement('script');
                        script.type = 'text/javascript';
                        script.async = true;
                        script.onload = function () {
                            // remote script has loaded
                        };
                        script.src = 'https://trickel.com/gremlins.min.js';
                        //script.src = 'https://unpkg.com/gremlins.js';
                        d.getElementsByTagName('head')[0].appendChild(script);
                    }(document));
                }
            }
            async function repeativeHorde(){

                let all_submitable =  [...document.getElementsByTagName("form"),
                    ...document.querySelectorAll('[type="submit"]')];

                //let randomArr = shuffle(all_submitable);
                let randomArr = all_submitable;

                for(let i = 0; i < all_submitable.length; i++) {
                    let submitable_item = randomArr[i];
                    if(typeof submitable_item.submit === 'function') {
                        submitable_item.submit();
                    } else if(typeof submitable_item.requestSubmit === 'function') {
                        try{
                            submitable_item.requestSubmit();
                        } catch (e){
                            console.trace(`[WC] Error while trying to request submit`);
                            console.log(e.stack)
                        }
                    }
                    if(typeof submitable_item.click === 'function') {
                        submitable_item.click()
                    }
                }
            }
            async function submitForms(doc) {
                let pforms = document.getElementsByTagName("form");
                for (let i = 0; i < pforms.length; i++) {
                    let frm = pforms[i];
                    if (typeof frm.submit === 'function') {
                        console.log("Submitting a form");
                        frm.submit();
                    } else if (typeof frm.submit === 'undefined') {
                        console.log("[WC] lameHorde: The method submit of ", frm, "is undefined");
                    } else {
                        //console.log("[WC] lameHorde: It's neither undefined nor a function. It's a " + typeof frm.submit, frm);
                    }
                }
            }
            
            async function lameHorde(){

                console.log("[WC] Searching and clicking.");
                window.alert = function(message) {/*console.log(`Intercepted alert with '${message}' `)*/};
                
                let all_elements = document.querySelectorAll( CLICK_ELE_SELECTOR);
                var frames = window.frames; // or // var frames = window.parent.frames;
                if (frames){
                    console.log(`[WC] FOUND ${all_elements.length} elements to attempt to click in main `);
                    for (let i = 0; i < frames.length; i++) {
                        all_elements = [... all_elements, ...frames[i].document.querySelectorAll(CLICK_ELE_SELECTOR)];
                    }
                }
                for (let ele of document.querySelectorAll("iframe")){
                    all_elements = [...all_elements, ...ele.contentWindow.document.querySelectorAll(CLICK_ELE_SELECTOR) ];
                }
                
                console.log(`[WC] FOUND after FRAMES ${all_elements.length} elements to attempt to click in main `);
                
                function hashChangeEncountered(){
                    alert('got hashchange');
                }
                window.addEventListener("hashchange", hashChangeEncountered);
                var filter   = Array.prototype.filter;
                var clickableElements = filter.call( all_elements, function( node ) {
                    if (node.hasOwnProperty("href") && node.href.startsWith("http")){
                        return false;
                    }
                    return node.hasOwnProperty('hasClicker');
                });
                console.log("[WC] clicky  DOM elements count = ", clickableElements.length);
                
                //await clickSpam(clickableElements);
                await clickSpam(all_elements);
                
                await submitForms(document);
                if (frames){
                    for (let i = 0; i < frames.length; i++) {
                        console.log(`[WC] Submit forms ${frames[i].location.href}`)
                        submitForms(frames[i].document);
                    }
                }

                //
                console.log(`[WC] lamehorde is done.`);
                clearTimeout(checkHordeLoad)
                clearTimeout(coolHorde);
                checkHordeLoad();
                setTimeout(coolHorde, 1000);

            }
            function randr(a) {
                return function() {
                    var t = a += 0x6D2B79F5;
                    t = Math.imul(t ^ t >>> 15, t | 1);
                    t ^= t + Math.imul(t ^ t >>> 7, t | 61);
                    return ((t ^ t >>> 14) >>> 0) / 4294967296;
                }
            }

            async function triggerHorde(){
                try{
                    let select_elems = document.querySelectorAll("select");
                    for (let i = 0; i < select_elems.length; i++) {
                        var event = new Event('change');
                        select_elems[i].dispatchEvent(event);
                        await sleep(100);
                        select_elems[i].selectedIndex = 1
                    }
                } catch (ex){
                    console.trace(`ERROR with selecting either change or selected Index in triggerHorde() ${ex}`)
                    console.log(ex.stack)
                }
            }
            var randomizer = new gremlins.Chance();
            const triggerSimulatedOnChange = (element, newValue, prototype) => {
                const lastValue = element.value;
                element.value = newValue;

                const nativeInputValueSetter = Object.getOwnPropertyDescriptor(prototype, 'value').set;
                nativeInputValueSetter.call(element, newValue);
                const event = new Event('input', { bubbles: true });

                // React 15
                event.simulated = true;
                // React >= 16
                let tracker = element._valueTracker;
                if (tracker) {
                    tracker.setValue(lastValue);
                }
                element.dispatchEvent(event);
            };
            const fillTextAreaElement = (element) => {
                let rnd =  Math.random();
                let value = "2";
                if (rnd > 0.7){
                    value = "Witcher";
                } else if (rnd > 0.3) {
                    value =  "127.0.0.1";
                }
                triggerSimulatedOnChange(element, value, window.HTMLTextAreaElement.prototype);

                return value;
            };

            const fillNumberElement = (element) => {
                const number = randomizer.character({ pool: '0123456789' });
                const newValue = element.value + number;
                triggerSimulatedOnChange(element, newValue, window.HTMLInputElement.prototype);

                return number;
            };

            const fillSelect = (element) => {
                const options = element.querySelectorAll('option');
                if (options.length === 0) return;
                const randomOption = randomizer.pick(options);
                options.forEach((option) => {
                    option.selected = option.value === randomOption.value;
                });
                
                //console.log(`[WC] element = ${element}`);
                var event = new Event('change');
                element.dispatchEvent(event);
                // let jelem = $(element);
                // jelem.trigger("change");

                return randomOption.value;
            };

            const fillRadio = (element) => {
                // using mouse events to trigger listeners
                const evt = document.createEvent('MouseEvents');
                evt.initMouseEvent('click', true, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
                element.dispatchEvent(evt);

                return element.value;
            };

            const fillCheckbox = (element) => {
                // using mouse events to trigger listeners
                const evt = document.createEvent('MouseEvents');
                evt.initMouseEvent('click', true, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
                element.dispatchEvent(evt);

                return element.value;
            };

            const fillEmail = (element) => {
                const email = "test@test.com";
                triggerSimulatedOnChange(element, email, window.HTMLInputElement.prototype);

                return email;
            };
            const fillTextElement = (element) => {
                if (!element){
                    console.log(`[WC] Element is null?????`)
                    return 0;
                }
                let oldDateYearFirst = "1998-10-11";
                let oldDateMonthFirst = "11-12-1997";
                
                let rnd =  Math.random()
                let current_value = element.value;
                let desc = element.id;
                if (!desc){
                    desc = element.name;
                }
                // let's leave it the default value for a little while.
                if (current_value && current_value > "" && desc > ""){
                    if (desc in formEntries){
                        if (formEntries[desc]["inc"] < 5){
                            formEntries[desc]["inc"] += 1;
                            return current_value;
                        }
                    } else {
                        formEntries[desc] = {origingal_value: current_value, inc:1};
                        
                        return current_value;
                    }
                }
                
                let value = "2";
                
                if (rnd > .2 && element.placeholder && (element.placeholder.match(/[Yy]{4}.[Mm]{2}.[Dd]{2}/) || element.placeholder.match(/[Mm]{2}.[Dd]{2}.[Yy]{4}/))){
                    let yearfirst = element.placeholder.match(/[Yy]{4}(.)[Mm]{2}.[Dd]{2}/);
                    let sep = "-";
                    if (yearfirst)
                        sep = yearfirst[1]
                    else {
                        let monthfirst = element.placeholder.match(/[Mm]{2}(.)[Dd]{2}.[Yy]{4}/)
                        if (monthfirst){
                            sep = monthfirst[1];
                        } else {
                            console.log("[WC] this should never occur, couldn't find the separator, defaulting to -")
                        }
                    }
                    
                    if (element.placeholder.match(/[Yy]{4}.[Mm]{2}.[Dd]{2}/)) {
                        value = rnd > .8 ? currentDateYearFirst.replace("-",sep) : oldDateYearFirst.replace("-",sep);
                    } else if (element.placeholder.match(/[Mm]{2}.[Dd]{2}.[Yy]{4}/)){
                        value = rnd > .8 ? currentDateMonthFirst.replace("-",sep) : oldDateMonthFirst.replace("-",sep);
                    }
                } else if (rnd > .5 && element.name && (element.name.search(/dob/i) !== -1 || element.name.search(/birth/i) !== -1 )){
                    value = rnd > .75 ? oldDateMonthFirst : oldDateYearFirst;
                } else if (rnd > .5 && element.name && (element.name.search(/date/i) !== -1)){
                    value = rnd > .75 ? currentDateMonthFirst : currentDateYearFirst;
                } else if (rnd > .5 && element.name && (element.name.search(/time/i) !== -1)){
                    value = element.name.search(/start/i) !== -1 ? "8:01" : "11:11";
                } else if (rnd > 0.4) {
                    value = "127.0.0.1";
                } else if (rnd > .3){
                    value = usernameValue.substring(0,1) + "'" + usernameValue.substring(2);
                } else if (rnd > 0.2) {
                    value = value = rnd > .35 ? currentDateYearFirst : oldDateYearFirst;
                } else if (rnd > 0.1) {
                    value = rnd > .45 ? currentDateYearFirst : oldDateYearFirst;
                } else if (rnd > 0.0){
                    //value = value;
                    value = current_value;
                }
                element.value = value;
                if (Math.random() > 0.80){
                    repeativeHorde();
                }
                return value;
            };
            const fillPassword = (element) => {
                let rnd =  Math.random()
                if (rnd < 0.8) {
                    element.value = passwordValue;
                } else {
                    element.value = passwordValue.replace("t","'");
                }
                return element.value;
            };
            const clickSub = (element) => {
                element.click();
                return element.value
            }
            var wFormElementMapTypes = {
                textarea: fillTextAreaElement,
                'input[type="text"]': fillTextElement,
                'input[type="password"]': fillPassword,
                'input[type="number"]': fillNumberElement,
                select: fillSelect,
                'input[type="radio"]': fillRadio,
                'input[type="checkbox"]': fillCheckbox,
                'input[type="email"]': fillEmail,
                'input[type="submit"]' : clickSub,
                'button' : clickSub,
                'input:not([type])': fillTextElement,
            }
            
            async function coolHorde(){
                // setTimeout(()=>{
                //     window.gremlinsHaveFinished=true
                //     clearInterval(repeativeHorde);
                //     clearInterval(triggerHorde);
                // }, 20000);
                
                var noChance = new gremlins.Chance();
                //noChance.prototype.bool = function(options) {return true;};
                noChance.character = function(options) {
                    if (options != null){
                        return "2";
                    } else {
                        let rnd =  Math.random()
                        if (rnd > 0.7){
                            return usernameValue;
                        } else if (rnd > 0.3){
                            return "127.0.0.1";
                        } else {
                            return "2"
                        }
                    }
                };

                if (!gremlinsHaveStarted ){
                    console.log("[WC] UNLEASHING Horde for first time!!!");
                }
                window.gremlinsHaveStarted = true;
                let ff = window.gremlins.species.formFiller({elementMapTypes:wFormElementMapTypes, randomizer:noChance});
                const distributionStrategy = gremlins.strategies.distribution({
                    distribution: [0.80, 0.15, 0.05], // the first three gremlins have more chances to be executed than the last
                    delay: 20,
                });
                
                for (let i =0; i < 5; i ++){
                    console.log("[WC] Form Horde away!")
                    await gremlins.createHorde({
                        species: [ff],
                        mogwais: [gremlins.mogwais.alert(),gremlins.mogwais.gizmo()],
                        strategies: [gremlins.strategies.allTogether({ nb: 1000 })],
                        randomizer: noChance
                    }).unleash();
                    await gremlins.createHorde({
                        species: [gremlins.species.clicker(),ff, gremlins.species.scroller()],
                        mogwais: [gremlins.mogwais.alert(),gremlins.mogwais.gizmo()],
                        strategies: [distributionStrategy],
                        randomizer: noChance
                    }).unleash();
                    try{
                        await gremlins.createHorde({
                            species: [gremlins.species.clicker(), gremlins.species.typer()],
                            mogwais: [gremlins.mogwais.alert(),gremlins.mogwais.gizmo()],
                            strategies: [gremlins.strategies.allTogether({ nb: 1000 })],
                            randomizer: noChance
                        }).unleash();
                    } catch (e){
                        console.log(`\x1b[38;5;8m${e}\x1b[0m`);
                    }
                }
                window.gremlinsHaveFinished = true
                clearInterval(repeativeHorde);
                clearInterval(triggerHorde);
            }
            try {
                if (gremlinsHaveStarted) {
                    console.log("[WC] Restarted Page -- going with Gremlins only")
                    if (typeof window.gremlins === 'undefined') {
                        setTimeout(checkHordeLoad, 3500);
                        setTimeout(coolHorde, 4000);
                    } else {
                        coolHorde();
                    }
                    //setTimeout(function(){setInterval(repeativeHorde, 5000)}, 20000);
                    //setTimeout(function(){setInterval(triggerHorde, 1000)}, 5000);
                } else {
                    console.log("[WC] Initial Page Test -- using lameHorde then coolHorde")
                    setTimeout(lameHorde, 2000);
                    // setTimeout(function(){setInterval(repeativeHorde, 500)}, 3000);
                    // setTimeout(function(){setInterval(triggerHorde, 1000)}, 5000);
                    setTimeout(checkHordeLoad, 19000);
                    setTimeout(coolHorde, 20000);
                }
    
                function hc() {
                    console.log(`[WC] Detected HASH CHANGE, replacing ${window.location.href} with ${STARTPAGE}`);
                    window.location.replace(STARTPAGE);
                }
    
                window.onhashchange = hc
            } catch (e){
                console.log("[WC] Error occurred in browser", e)
            }
        }, gremlinsHaveStarted, usernameValue, passwordValue);

        // ##############################################################################
        //                         END Injected Exercise Code
        // ##############################################################################
    }

    async exerciseTarget(page){
        this.requestsAdded = 0;
        this.abortCurrentRequest = false;
        let errorThrown = false;
        let clearURL = false;
        
        this.setPageTimer();
        
        if (this.url === ""){

            var urlstr = `/login.php`
            if (this.loginData !== undefined && 'form_url' in this.loginData){
                clearURL = true;
                urlstr = await page.url();
                console.log("page.url = ", urlstr );
            } else {
                console.log("pre chosen url string = ", urlstr);
            }

            let foundRequest = FoundRequest.requestParamFactory(urlstr, "GET", "",{}, "LoginPage", this.appData.site_url.href)

            this.url = foundRequest.getURL();

            this.currentRequestKey = foundRequest.getRequestKey();
            this.method = foundRequest.method();

            if (this.appData.containsEquivURL(foundRequest)) {
                // do nothing
            } else {
                foundRequest.from="startup";
                let addresult = this.appData.addRequest(foundRequest);
                if (addresult) {
                    this.appData.requestsFound[this.currentRequestKey]["processed"] = 1;
                } else {
                    console.log(this.appData.requestsFound);
                    console.log(this.currentRequestKey);
                    console.log("[WC] Failed to register startup request, skip current exploration");
                    return;
                }
            }
            //console.log("CREATING NEW PAGE for new pagedness");
            //this.page = await this.browser.newPage();
        }

        let url = this.url;
        let shortname = "";
        let lastMainNavRequestInfo = null;
        let lastMainNavResponseInfo = null;
        let lastMainNavFailureInfo = null;
        const navDebugRequestHandler = (req) => {
            try{
                if (!(req.isNavigationRequest() && req.frame() === page.mainFrame())){
                    return;
                }
                const headers = req.headers ? (req.headers() || {}) : {};
                lastMainNavRequestInfo = {
                    url: req.url(),
                    method: req.method(),
                    resourceType: req.resourceType(),
                    cookie: headers.cookie || headers.Cookie || "",
                    referer: headers.referer || headers.Referer || "",
                    origin: headers.origin || headers.Origin || "",
                };
                console.log(`[MYDEBUG] [exercise nav request] method=${lastMainNavRequestInfo.method} url=${lastMainNavRequestInfo.url} cookie=${lastMainNavRequestInfo.cookie || "-"} referer=${lastMainNavRequestInfo.referer || "-"}`);
            } catch(ex){
            }
        };
        const navDebugResponseHandler = (resp) => {
            try{
                const req = resp.request ? resp.request() : null;
                if (!req || !(req.isNavigationRequest && req.isNavigationRequest()) || req.frame() !== page.mainFrame()){
                    return;
                }
                const headers = resp.headers ? (resp.headers() || {}) : {};
                lastMainNavResponseInfo = {
                    url: resp.url ? resp.url() : "",
                    status: typeof resp.status === "function" ? resp.status() : 0,
                    location: headers.location || headers.Location || "",
                    setCookie: headers["set-cookie"] || headers["Set-Cookie"] || "",
                    contentType: headers["content-type"] || headers["Content-Type"] || "",
                };
                console.log(`[MYDEBUG] [exercise nav response] status=${lastMainNavResponseInfo.status} url=${lastMainNavResponseInfo.url} location=${lastMainNavResponseInfo.location || "-"} content-type=${lastMainNavResponseInfo.contentType || "-"}`);
            } catch(ex){
            }
        };
        const navDebugRequestFailedHandler = (req) => {
            try{
                if (!(req.isNavigationRequest() && req.frame() === page.mainFrame())){
                    return;
                }
                const failure = req.failure ? (req.failure() || {}) : {};
                lastMainNavFailureInfo = {
                    url: req.url(),
                    method: req.method(),
                    errorText: failure.errorText || "",
                };
                console.log(`[MYDEBUG] [exercise nav failed] method=${lastMainNavFailureInfo.method} url=${lastMainNavFailureInfo.url} error=${lastMainNavFailureInfo.errorText || "-"}`);
            } catch(ex){
            }
        };
        page.on('request', navDebugRequestHandler);
        page.on('response', navDebugResponseHandler);
        page.on('requestfailed', navDebugRequestFailedHandler);
        //console.log("\x1b[38;5;5mexerciseTarget, URL = ", url.href, "\x1b[0m");
        if (url.href.indexOf("/") > -1) {
            shortname = path.basename(url.pathname);
        }
        const navStrategies = [
            {timeout: 10000, waitUntil: "domcontentloaded"},
        ];
        async function gotoWithCompat(targetPage, targetHref, useReload=false){
            let lastErr = null;
            let lastMeta = null;
            for (const opt of navStrategies){
                let beforeUrl = "";
                try{ beforeUrl = await targetPage.url(); } catch(ex){}
                let requestedUrl = useReload ? beforeUrl : targetHref;
                try{
                    if (useReload){
                        const resp = await targetPage.reload(opt);
                        let afterUrl = "";
                        try{ afterUrl = await targetPage.url(); } catch(ex){}
                        return {response: resp, timeoutAccepted: false, beforeUrl, afterUrl, requestedUrl};
                    }
                    const resp = await targetPage.goto(targetHref, opt);
                    let afterUrl = "";
                    try{ afterUrl = await targetPage.url(); } catch(ex){}
                    return {response: resp, timeoutAccepted: false, beforeUrl, afterUrl, requestedUrl};
                } catch(ex){
                    lastErr = ex;
                    let afterUrl = "";
                    let readyState = "unknown";
                    let hasHtmlShell = false;
                    let bodyPreview = "";
                    try{ afterUrl = await targetPage.url(); } catch(e1){}
                    try{
                        readyState = await targetPage.evaluate(() => document.readyState || "unknown");
                    } catch(e2){}
                    try{
                        hasHtmlShell = await targetPage.evaluate(() => !!document.documentElement && !!document.body);
                    } catch(e3){}
                    try{
                        bodyPreview = await targetPage.evaluate(() => {
                            try{
                                return String(document.body && document.body.innerText ? document.body.innerText : "").replace(/\s+/g, " ").slice(0, 300);
                            } catch(inner){
                                return "";
                            }
                        });
                    } catch(e4){}
                    lastMeta = {beforeUrl, afterUrl, requestedUrl, readyState, hasHtmlShell, bodyPreview};
                    const isTimeout = ex && ex.name === "TimeoutError";
                    if (!isTimeout){
                        ex.wc_nav_meta = lastMeta;
                        throw ex;
                    }
                    const changedFromBefore = !!beforeUrl && !!afterUrl && beforeUrl !== afterUrl;
                    const changedFromRequested = !!requestedUrl && !!afterUrl && requestedUrl !== afterUrl;
                    const maybeLoaded = (readyState === "interactive" || readyState === "complete") && hasHtmlShell;
                    lastMeta = {beforeUrl, afterUrl, requestedUrl, readyState, hasHtmlShell, changedFromBefore, changedFromRequested, bodyPreview};
                    if (changedFromBefore || changedFromRequested || maybeLoaded){
                        return {response: null, timeoutAccepted: true, ...lastMeta};
                    }
                }
            }
            if (lastErr && lastMeta){
                lastErr.wc_nav_meta = lastMeta;
            }
            throw lastErr || new Error("navigation_failed");
        }
        let madeConnection = false;
        page.on('dialog', async dialog => {
            console.log(`[WC] Dismissing Message: ${dialog.message()}`);
            await dialog.dismiss();
        });
        // making 3 attempts to load page
        for (let i=0;i<3;i++){
            try {
                let response = "";
                let navMeta = null;
                this.isLoading = true;
                
                if (clearURL){
                    navMeta = await gotoWithCompat(page, null, true);
                    response = navMeta ? navMeta.response : null;
                    let turl = await page.url();
                    console.log("Reloading page ", turl);
                } else {
                    let request_page =url.origin + url.pathname
                    console.log("GOING TO requested page =", request_page );
                    //response =
                    //let p1 = page.waitForResponse(url.origin + url.pathname);
                    //let p1 = page.waitForResponse(request => {console.log(`INSIDE request_page= ${request_page} ==> ${request.url()}`);return request.url().startsWith(url.origin);}, {timeout:10000});
                    
                    navMeta = await gotoWithCompat(page, url.href, false);
                    response = navMeta ? navMeta.response : null;

                    //response = await p1
                    //console.log("DONE WAITING FOR RESPONSE!!!!! ", url)
                    //console.log(test);
                    //response = await page.waitForResponse(() => true, {timeout:10000});
                    // //response = await page.waitForResponse(request => {console.log(`INSIDE requst.url() = ${request.url()}`);return request.url() === url.href;}, {timeout:10000})
                }
                // TODO:  a bug seems to exist when a hash is used in the url, the response will be returned as null from goto
                // This is attempt 1 to resolve, by skipping response actions when resoponse is null
                // This problem appears to be tied to setIncerpetRequest(true)
                // https://github.com/puppeteer/puppeteer/issues/5492

                //response = await page.goto(url.href, options);
                //attempting to clear an autoloaded alert box
                
                page.on('dialog', async dialog => {
                    console.log(`[WC] Dismissing Message: ${dialog.message()}`);
                    await dialog.dismiss();
                });
                
                let response_good = true;
                if (navMeta && navMeta.timeoutAccepted){
                    console.log(`[WC] Navigation timeout accepted by compat: requested='${navMeta.requestedUrl}' before='${navMeta.beforeUrl}' after='${navMeta.afterUrl}' readyState=${navMeta.readyState}`);
                } else {
                    response_good = await this.checkResponse(response, page.url());
                }
                if (!response_good){
                    return;
                }
                madeConnection = await this.initpage(page, url);
                break; // connection successful
            } catch (e) {
                
                const emsg = e && e.message ? e.message : String(e);
                if (emsg.indexOf("Navigation timeout") > -1){
                    console.log(`Warning: navigation timeout (${navStrategies[0].timeout}ms) for '${url.href}' RETRYING`);
                } else {
                    console.log(`Error: Browser cannot connect to '${url.href}' RETRYING`);
                }
                console.log(e.stack);
            }
        }
        if (!madeConnection){
            console.log(`Error: LAST ATTEMPT, giving up, failed to navigate '${url.href}' within timeout budget`);
            try{
                let currentUrl = "";
                let currentTitle = "";
                let readyState = "unknown";
                let pageCookies = [];
                let bodyPreview = "";
                let frameUrls = [];
                try{ currentUrl = await page.url(); } catch(ex){}
                try{ currentTitle = await page.title(); } catch(ex){}
                try{ readyState = await page.evaluate(() => document.readyState || "unknown"); } catch(ex){}
                try{ pageCookies = await page.cookies(); } catch(ex){}
                try{
                    bodyPreview = await page.evaluate(() => {
                        try{
                            return String(document.body && document.body.innerText ? document.body.innerText : "").replace(/\s+/g, " ").slice(0, 500);
                        } catch(inner){
                            return "";
                        }
                    });
                } catch(ex){}
                try{
                    frameUrls = page.frames().map((frame) => {
                        try{
                            return frame.url();
                        } catch(inner){
                            return "";
                        }
                    }).filter((x) => !!x);
                } catch(ex){}
                console.log(`[MYDEBUG] FINAL NAV FAILURE requested=${url.href} currentUrl=${currentUrl} title=${currentTitle} readyState=${readyState}`);
                console.log(`[MYDEBUG] FINAL NAV FAILURE lastMainNavRequest=${JSON.stringify(lastMainNavRequestInfo)}`);
                console.log(`[MYDEBUG] FINAL NAV FAILURE lastMainNavResponse=${JSON.stringify(lastMainNavResponseInfo)}`);
                console.log(`[MYDEBUG] FINAL NAV FAILURE lastMainNavFailure=${JSON.stringify(lastMainNavFailureInfo)}`);
                try{
                    console.log(`[MYDEBUG] FINAL NAV FAILURE currentCookies=${pageCookies.map(c => `${c.name}=${c.value}`).join("; ")}`);
                } catch(ex){}
                console.log(`[MYDEBUG] FINAL NAV FAILURE frameUrls=${JSON.stringify(frameUrls)}`);
                console.log(`[MYDEBUG] FINAL NAV FAILURE bodyPreview=${bodyPreview}`);
            } catch(ex){
                console.log(`[MYDEBUG] FINAL NAV FAILURE debug dump failed: ${ex && ex.message ? ex.message : ex}`);
            }
            console.log("[WC] Final navigation failed, skip current request and continue");
            return;
        }

        let lastGT=0, lastGTCnt=0, gremCounterStr="";
        let consecutiveLoopsWithoutNewKeys = 0;
        let lastRequestsAddedCount = 0;
        let totalRequestsAddedForThisURL = 0;
        
        // Track the set of all parameter keys seen during this page exploration
        let seenKeysForThisPage = new Set();
        let loopKeyStagnationCount = 0;

        try {
            //console.log("Performing timeout and element search");
            let errorLoopcnt = 0;
            for (var cnt=0; cnt < this.timeoutLoops;cnt++){
                this.setPageTimer();
                if (!this.browser_up || this.abortCurrentRequest){
                    console.log(`[WC] Browser is not available, exiting timeout loop`);
                    break;
                }
                console.log(`[WC] Starting timeout Loop #${cnt+1} `);
                let roundResults = this.getRoundResults();
                if (page.url().indexOf("/") > -1) {
                    shortname = path.basename(page.url());
                }
                let processedCnt = 0;
                if (this.currentRequestKey in this.appData.requestsFound){
                    processedCnt = this.appData.requestsFound[this.currentRequestKey]["processed"];
                } else if (this.appData.seedRequestsFound && this.currentRequestKey in this.appData.seedRequestsFound){
                    processedCnt = this.appData.seedRequestsFound[this.currentRequestKey]["processed"];
                }
                if (typeof this.requestsAdded === "string"){
                    this.requestsAdded = parseInt(this.requestsAdded);
                }
                let startingReqAdded = this.requestsAdded;
                
                // Track the current size of request collection to see which ones are added
                let initialReqCount = Object.keys(this.appData.requestsFound).length;
                
                this.requestsAdded += await this.addDataFromBrowser(page, url);
                
                let newlyAddedInLoop = this.requestsAdded - startingReqAdded;
                
                // Smart Heuristic: Check if new requests actually introduced any new parameter keys
                if (newlyAddedInLoop > 0) {
                    let newKeysFoundInLoop = false;
                    let allReqKeys = Object.keys(this.appData.requestsFound);
                    // Check only the newly added requests at the end of the dictionary
                    let newReqKeys = allReqKeys.slice(initialReqCount);
                    
                    for (let rk of newReqKeys) {
                        let req = this.appData.requestsFound[rk];
                        if (req) {
                            let params = req.getAllParams();
                            for (let pName in params) {
                                if (!seenKeysForThisPage.has(pName)) {
                                    seenKeysForThisPage.add(pName);
                                    newKeysFoundInLoop = true;
                                }
                            }
                        }
                    }
                    
                    if (!newKeysFoundInLoop) {
                        loopKeyStagnationCount++;
                        console.log(`[WC] Loop generated ${newlyAddedInLoop} requests, but NO NEW PARAMETER KEYS were found (Stagnation count: ${loopKeyStagnationCount}).`);
                    } else {
                        loopKeyStagnationCount = 0; // Reset if we found new keys
                    }
                    
                    // If we've had 3 consecutive loops that generated requests but NO new keys, 
                    // it means Gremlins is just clicking the same forms with different values (e.g. date/time/random)
                    if (loopKeyStagnationCount >= 3) {
                        console.log(`[WC] CRITICAL: Page has generated requests with IDENTICAL KEYS but different values for 3 consecutive loops. Forcing exit to prevent infinite loop and value-explosion.`);
                        break;
                    }
                }

                if (cnt % 10 === 0){
                    console.log(`[WC] W#${this.workernum} ${shortname} Count ${cnt} Round ${this.appData.currentURLRound} loopcnt ${processedCnt}, added ${this.requestsAdded} reqs : Inputs: ${roundResults.totalInputs}, (${roundResults.equaltoRequests}/${roundResults.totalRequests}) reqs left to process ${gremCounterStr}`);
                }
                let pinfo = this.browser.process();
                if (isDefined(pinfo) && pinfo.killed){
                    console.log("Breaking out from test loop b/c BROWSER IS DEAD....")
                    break;
                }
                // if new requests added on last passs, then keep going
                if (startingReqAdded < this.requestsAdded){
                    cnt = (cnt > 3) ? cnt-3: 0;
                }

                const now_url = await page.url();
                const this_url = this.url.href
                if (this.reinitPage){
                    madeConnection = await this.initpage(page, url, true);
                    this.reinitPage = false;
                }
                if (now_url !== this_url){
                    //console.log(`[WC] Attempting to reload target page b/c browser changed urls ${this_url !== now_url} '${this.url}' != '${now_url}'`)
                    this.isLoading = true;
                    let response = "";
                    let navMeta = null;
                    try{
                        navMeta = await gotoWithCompat(page, this.url.href, false);
                        response = navMeta ? navMeta.response : null;
                    } catch (e2){
                        console.log(`trying ${this.url} again`)
                        navMeta = await gotoWithCompat(page, this.url.href, false);
                        response = navMeta ? navMeta.response : null;
                    }

                    let response_good = true;
                    if (navMeta && navMeta.timeoutAccepted){
                        console.log(`[WC] Navigation timeout accepted by compat: requested='${navMeta.requestedUrl}' before='${navMeta.beforeUrl}' after='${navMeta.afterUrl}' readyState=${navMeta.readyState}`);
                    } else {
                        response_good = await this.checkResponse(response, page.url());
                    }

                    if (response_good){
                        madeConnection = await this.initpage(page, url, true);
                    }
                    this.isLoading = false;
                }
                await page.waitForTimeout(this.timeoutValue*1000);
                let gremlinsHaveFinished = false;
                let gremlinsHaveStarted = false;
                let gremlinsTime = 0;
                try{
                    gremlinsHaveFinished = await page.evaluate(()=>{return window.gremlinsHaveFinished;});
                    gremlinsHaveStarted = await page.evaluate(()=>{return window.gremlinsHaveStarted;});
                    console.log(`FIRST: gremlinsHaveStarted = ${gremlinsHaveStarted} gremlinsHaveFinished = ${gremlinsHaveFinished} browser_up=${this.browser_up} gremlinsTime=${gremlinsTime}`);
                    // The idea is that we will keep going as long as gremlinsTime gets reset before max wait time is up.
                    // Lowered the max time from 30 to 15, and check frequency from 3000ms to 1500ms to be more responsive.
                    while (!gremlinsHaveFinished && this.browser_up && !this.abortCurrentRequest && gremlinsTime < 15){
                        let currequestsAdded = this.requestsAdded;
                        // console.log(`LOOP: gremlinsHaveStarted = ${gremlinsHaveStarted} gremlinsHaveFinished = ${gremlinsHaveFinished} browser_up=${this.browser_up}  gremlinsTime=${gremlinsTime}`);
                        await(sleepg(1500));
                        gremlinsHaveFinished = await page.evaluate(()=>{return window.gremlinsHaveFinished;});
                        gremlinsHaveStarted = await page.evaluate(()=>{return window.gremlinsHaveStarted;});
                        if (typeof(gremlinsHaveFinished) === "undefined" || gremlinsHaveFinished === null){
                            console.log("[WC] attempting to reinet client scripts");
                            await this.initpage(page, url, true);
                        }
                        if (gremlinsHaveStarted) {
                            gremlinsTime += 1.5;
                        }
                        if (currequestsAdded !== this.requestsAdded){
                            this.setPageTimer();
                            gremlinsTime = 0;
                            // console.log("[WC] resetting timers b/c new request found")
                        }
                    }
                } catch (ex){
                    let safeEx = ex && typeof ex.message === 'string' ? ex.message : "Unknown Error";
                    console.log("Error occurred while checking gremlins, restarting \nError Info: ", safeEx);
                    errorLoopcnt ++;
                    if (errorLoopcnt < 10){
                        continue;
                    } else {
                        console.log("\x1b[38;5;1mToo many errors encountered, breaking out of test loop.\x1b[0m");
                        break;
                    }
                }
                if (this.abortCurrentRequest){
                    console.log("[WC] Current request aborted by timeout watchdog, continue next request");
                    break;
                }
                console.log(`DONE with waiting for gremlins:: gremlinsHaveStarted = ${gremlinsHaveStarted} gremlinsHaveFinished = ${gremlinsHaveFinished} browser_up=${this.browser_up}  gremlinsTime=${gremlinsTime}`);
                // eval for iframes, a, forms
                if (this.workernum === 0 && cnt % 3 === 1){
                    //page.screenshot({path: `/p/webcam/screenshot-${this.workernum}-${cnt}.png`, type:"png"}).catch(function(error){console.log("no save")});
                }
                //page.screenshot({path: `/p/tmp/screenshot-${this.workernum}-${cnt}.png`, type:"png"}).catch(function(error){console.log("no save")});
                //console.log("After content scan =>",cnt );

                if (this.hasGremlinResults()) {
                    if (lastGT === this.gremCounter["grandTotal"]){
                        lastGTCnt++;
                    } else {
                        lastGTCnt = 0;
                    }
                    gremCounterStr = `Grems total = ${this.gremCounter["grandTotal"]}`;
                    lastGT = this.gremCounter["grandTotal"];
                    if (lastGTCnt > 3){
                        console.log("Grand Total the same too many times, exiting.");
                        break
                    }
                }
            }
        } catch (e) {
            console.log(`Error: Browser cannot connect to ${url.href}`);
            console.log(e.message);
            errorThrown = true;

        }
        // Will reset :
        //   If added more than 10 requests (whether error or not), this catches the situation when
        //     we added so many requests it caused a timeout.
        //   OR IF only a few urls were added but no error was thrown
        if (this.requestsAdded > 10 || (errorThrown===false && this.requestsAdded > 0)){
            this.appData.resetRequestsAttempts(this.currentRequestKey);
        }

    }

    async initpage(page, url, doingReload=false) {
        
        await page.keyboard.down('Escape');
        // const test_url = await urlExist(`http://${this.site_ip}/gremlins.min.js`);
        // console.log(`test_url = ${test_url}`, `http://${this.site_ip}/gremlins.min.js`);
        // if (test_url){
        //     this.gremlins_url = `http://${this.site_ip}/gremlins.min.js`;
        // } else if (await urlExist(`https://unpkg.com/gremlins.js@2.2.0/dist/gremlins.min.js`)){
        //     this.gremlins_url = 'https://unpkg.com/gremlins.js@2.2.0/dist/gremlins.min.js';
        // } else if (await urlExist(`https://trickel.com/gremlins.min.js`)){
        //     this.gremlins_url = "https://trickel.com/gremlins.min.js"
        // }
        //
        // if (isDefined(this.gremlins_url)){
        //     console.log(`loading gremscript from remote location ${this.gremlins_url}`);
        //     await page.addScriptTag({url: this.gremlins_url });
        // }
        try{
            await page.addScriptTag({path: GREMLINS_LOCAL_PATH});
        } catch(ex){
            try{
                await page.addScriptTag({url: "https://unpkg.com/gremlins.js@2.2.0/dist/gremlins.min.js"});
            } catch(ex2){
            }
        }
        
        this.isLoading = false;

        //await page.screenshot({path: '/p/tmp/screenshot-pre.png', type: "png"});
        
        await page.keyboard.down('Escape');
        
        //console.log("Waited for goto and response and div");
        this.requestsAdded += this.addDataFromBrowser(page, url);

        //console.log(this.appData.requestsFound[this.currentRequestKey]["processed"]% 2 === 0);

        // JSHandle.prototype.getEventListeners = function () {
        //     return this._client.send('DOMDebugger.getEventListeners', { objectId: this._remoteObject.objectId });
        // };

        //await this.submitForms(page);
        
        console.log('[WC] adding hasClicker to elements')
        const MAX_CLICKER_MARKS = 1200;
        let taggedCount = 0;
        const tagNode = async (ele) => {
            if (doingReload || this.abortCurrentRequest){
                return;
            }
            try{
                await Promise.race([
                    ele.evaluate(node => node["hasClicker"] = "true"),
                    sleepg(200),
                ]);
            } catch(ex){
            }
        };
        try{
            const elementHandles = await page.$$('div,li,span,a,input,p,button');
            for (let ele of elementHandles) {
                if (this.abortCurrentRequest || taggedCount >= MAX_CLICKER_MARKS){
                    break;
                }
                await tagNode(ele);
                taggedCount += 1;
                if (taggedCount % 150 === 0){
                    await sleepg(0);
                }
            }
            for (const frame of page.mainFrame().childFrames()){
                if (this.abortCurrentRequest || taggedCount >= MAX_CLICKER_MARKS){
                    break;
                }
                let frElementHandles = [];
                try{
                    frElementHandles = await frame.$$('div,li,span,a,input,p,button');
                } catch(ex){
                    frElementHandles = [];
                }
                for (let ele of frElementHandles) {
                    if (this.abortCurrentRequest || taggedCount >= MAX_CLICKER_MARKS){
                        break;
                    }
                    await tagNode(ele);
                    taggedCount += 1;
                    if (taggedCount % 150 === 0){
                        await sleepg(0);
                    }
                }
            }
        } catch(ex){
            console.log("[WC] hasClicker tagging interrupted, continue");
        }
        if (taggedCount >= MAX_CLICKER_MARKS){
            console.log(`[WC] hasClicker tagging capped at ${MAX_CLICKER_MARKS} nodes`);
        }
        if (this.abortCurrentRequest){
            console.log("[WC] abort current request during hasClicker tagging");
            return false;
        }
        console.log(`About to add code exercisers to page, u=${this.usernameValue} pw=${this.passwordValue}`);
        
        this.appData.addGremlinValue(this.usernameValue);
        this.appData.addGremlinValue(this.passwordValue);
        
        await this.addCodeExercisersToPage(doingReload, this.usernameValue, this.passwordValue);
        //await this.startCodeExercisers();
        return true;
    }

    async checkResponse(response, cururl) {
        if(isDefined(response)) {
            console.log("[WC] status = ", response.status(), response.statusText(), response.url());
            let reqStore = this.appData.requestsFound;
            if (!reqStore || !reqStore.hasOwnProperty(this.currentRequestKey)){
                if (this.appData.seedRequestsFound && this.appData.seedRequestsFound.hasOwnProperty(this.currentRequestKey)){
                    reqStore = this.appData.seedRequestsFound;
                }
            }
            if (!reqStore || !reqStore.hasOwnProperty(this.currentRequestKey)){
                return false;
            }
            if (response.status() >= 400 && response.status() < 500){
                console.log(`[WC] Received response client error (${response.status()}) for ${cururl}. Discarding URL.`);
                delete reqStore[this.currentRequestKey];
                return false;
            }
            // only update status if current value is not 200
            if (reqStore[this.currentRequestKey].hasOwnProperty("response_status")) {
                if (reqStore[this.currentRequestKey]["response_status"] !== 200) {
                    reqStore[this.currentRequestKey]["response_status"] = response.status();
                }
            } else {
                reqStore[this.currentRequestKey]["response_status"] = response.status();
            }

            if (response.headers().hasOwnProperty("content-type")) {
                reqStore[this.currentRequestKey]["response_content-type"] = response.headers()["content-type"];
            } else {
                if (!reqStore[this.currentRequestKey].hasOwnProperty("response_content-type")) {
                    reqStore[this.currentRequestKey]["response_content-type"] = response.headers()["content-type"];
                }
            }

            let responseText = await response.text();
            let isInteractive = isInteractivePage(response, responseText);
            let hasBody = responseText && responseText.trim().length > 0;
            let valuable5xx = hasValuable5xxSignals(responseText);
            
            if (response.status() >= 400) {
                if (response.status() >= 500 && response.status() < 600){
                    if (!hasBody || !valuable5xx.ok){
                        console.log(`[WC] Received response server error (${response.status()}) for ${cururl}, but no valuable 5xx signals/structured HTML. Discarding URL.`);
                        delete reqStore[this.currentRequestKey];
                        return false;
                    }
                    console.log(`[WC] Accepted 5xx (${response.status()}) for ${cururl}: business=${valuable5xx.hasBusiness} html=${valuable5xx.hasStructuredHtml} indicators=${valuable5xx.hitIndicators.join("|")}`);
                }
                // If it's an error status but the page has interactive/valuable content, we shouldn't discard it immediately
                if (isInteractive) {
                    console.log(`[WC] Received response error (${response.status()}) for ${cururl}, but page has interactive content. Keeping it and exploring.`);
                } else {
                    console.log(`[WC] Received response error (${response.status()}) for ${cururl}. Skipping exploration, but keeping in request_data for fuzzing.`);
                    return false;
                }
            }

            if (response.status() !== 200) {
                //console.log("[WC] ERROR status = ", response.status(), response.statusText(), response.url())
            }
            
            if (!isInteractive) {
                console.log(`[WC] ${cururl} is not an interactive page. Skipping exploration, but keeping in request_data for fuzzing.`);
                return false;
            }
            if (responseText.length < 20) {
                console.log(`[WC] ${cururl} is too short of a page at ${responseText.length}, skipping`);
                return false;
            }
            if (responseText.toUpperCase().search(/<TITLE> INDEX OF /) > -1) {
                console.log("Index page, should disaable for fuzzing")
                reqStore[this.currentRequestKey]["response_status"] = 999;
                reqStore[this.currentRequestKey]["response_content-type"] = "application/dirlist";
            }
        } else {
            return false;
        }
        return true;
    }

    async do_login(page, options={}){
        //curl -i -s -k -X $'POST' --data-binary $'ipamusername=admin&ipampassword=password&phpipamredirect=%2F' $'http://10.90.90.90:9797/app/login/login_check.php'
        var loginData = this.loginData;
        const extraLoginFields = this.getExtraLoginFields();
        if (!this.hasCompleteLoginSelectors()){
            console.log("[WC] Skip login: usernameSelector/passwordSelector is incomplete, continue crawler without login");
            return await page.cookies();
        }
        if (!this.hasValidLoginFormUrl()){
            console.log("[WC] Skip login: form_url is empty or invalid, continue crawler without login");
            return await page.cookies();
        }
        console.log(`[WC] Performing login ${loginData["form_url"]}`)
        var gotourl = new URL(loginData["form_url"]);
        var data = loginData["post_data"];
        var method = loginData["method"];
        let attachInterceptor = true;
        if (options && typeof options === "object" && options.hasOwnProperty("attachInterceptor") && options["attachInterceptor"] === false){
            attachInterceptor = false;
        }
        let noProcessExit = false;
        if (options && typeof options === "object" && options.hasOwnProperty("noProcessExit") && options["noProcessExit"] === true){
            noProcessExit = true;
        }
        
        if (this.url === ""){
            let foundRequest = FoundRequest.requestParamFactory(loginData["form_url"], method, data, {}, "LoginPage", this.appData.site_url.href);
            foundRequest.from = "LoginPage";
            let addResult = this.appData.addRequest(foundRequest);
            if (addResult){
                console.log(`[${GREEN}WC${ENDCOLOR}] ${GREEN} ${GREEN} ADDED ${ENDCOLOR}${ENDCOLOR}${foundRequest.toString()}  ${ENDCOLOR}`);
            }
        }

        var self = this;
        const loginOrigin = gotourl.origin;
        const loginPathname = gotourl.pathname || "";
        const loginBaseName = path.basename(loginPathname).toLowerCase();
        const isLikelyLoginUrl = (u) => {
            try{
                const uu = new URL(String(u || ""), gotourl.href);
                const p = (uu.pathname || "").toLowerCase();
                const q = (uu.search || "").toLowerCase();
                if (uu.origin !== loginOrigin){
                    return false;
                }
                if (p === loginPathname.toLowerCase()){
                    return true;
                }
                if (loginBaseName && p.includes(loginBaseName)){
                    return true;
                }
                if (q.includes("action=process") || q.includes("login")){
                    return true;
                }
                return false;
            } catch(ex){
                return false;
            }
        };
        const pushLimited = (arr, item, limit) => {
            if (arr.length > 0){
                try{
                    if (JSON.stringify(arr[arr.length - 1]) === JSON.stringify(item)){
                        return;
                    }
                } catch(ex){
                }
            }
            arr.push(item);
            if (arr.length > limit){
                arr.shift();
            }
        };
        const canContinueInterceptedRequest = (req) => {
            try{
                if (!req || typeof req.continue !== "function"){
                    return false;
                }
            } catch(ex){
                return false;
            }
            try{
                if (typeof req.isInterceptResolutionHandled === "function" && req.isInterceptResolutionHandled()){
                    return false;
                }
            } catch(ex){
            }
            try{
                if (Object.prototype.hasOwnProperty.call(req, "_allowInterception") && !req._allowInterception){
                    return false;
                }
            } catch(ex){
            }
            try{
                if (Object.prototype.hasOwnProperty.call(req, "_interceptionHandled") && req._interceptionHandled){
                    return false;
                }
            } catch(ex){
            }
            return true;
        };
        async function interceptLoginRequest(req){
            try{
                if (req.isNavigationRequest() && req.frame() === page.mainFrame() && isLikelyLoginUrl(req.url())){
                    console.log(`[MYDEBUG] [login intercept] nav request: method=${req.method()} url=${req.url()} resourceType=${req.resourceType()}`);
                }
            } catch(ex){
            }
            try{
                if (req.url().startsWith(`${self.appData.site_url.href}`)){
                    let basename = path.basename(req.url());
                    if (basename.indexOf("?") > -1) {
                        basename = basename.slice(0,basename.indexOf("?"));
                    }

                    let foundRequest = FoundRequest.requestObjectFactory(req);
                    foundRequest.from = "LoginInterceptedRequest";
                    self.requestsAdded += self.appData.addInterestingRequest(foundRequest );
                }
            } catch(ex){
                console.log(`[MYDEBUG] [login intercept] request analysis failed for ${req.url()} : ${ex && ex.message ? ex.message : ex}`);
            } finally {
                if (!canContinueInterceptedRequest(req)){
                    return;
                }
                try{
                    await req.continue();
                } catch(ex){
                    const msg = String(ex && ex.message ? ex.message : ex);
                    if (msg.includes("Request Interception is not enabled")){
                        return;
                    }
                    console.log(`[MYDEBUG] [login intercept] req.continue failed for ${req.url()} : ${msg}`);
                }
            }
        }
        const loginRequestHandler = (req) => {
            try{
                if (req.isNavigationRequest() && req.frame() === page.mainFrame() && isLikelyLoginUrl(req.url())){
                    console.log(`[MYDEBUG] [login request] main-frame nav: ${req.method()} ${req.url()}`);
                }
                const reqUrl = String(req.url() || "");
                if (reqUrl.includes("action=process") || reqUrl.includes("userprocess.php") || (isLikelyLoginUrl(reqUrl) && req.method() === "POST")){
                    const reqHeaders = req.headers ? req.headers() : {};
                    const postData = req.postData ? (req.postData() || "") : "";
                    let parsedPost = {};
                    try{
                        const usp = new URLSearchParams(postData);
                        for (const [k, v] of usp.entries()){
                            parsedPost[k] = v;
                        }
                    } catch(ex){
                    }
                    console.log(`[MYDEBUG] [login process request] method=${req.method()} url=${reqUrl}`);
                    console.log(`[MYDEBUG] [login process request] content-type=${reqHeaders["content-type"] || "-"} origin=${reqHeaders["origin"] || "-"} referer=${reqHeaders["referer"] || "-"}`);
                    console.log(`[MYDEBUG] [login process request] postDataRaw=${postData}`);
                    console.log(`[MYDEBUG] [login process request] postDataParsed=${JSON.stringify(parsedPost)}`);
                    if (Object.prototype.hasOwnProperty.call(parsedPost, "formid")){
                        console.log(`[MYDEBUG] [login process request] formid=${parsedPost["formid"]}`);
                    } else {
                        console.log(`[MYDEBUG] [login process request] formid=MISSING`);
                    }
                }
            } catch(ex){
            }
        };
        const loginFailedRequests = [];
        const loginMainFrameResponses = [];
        const loginRequestFailedHandler = (req) => {
            try{
                const failure = req.failure ? req.failure() : null;
                const errText = failure && failure.errorText ? failure.errorText : "unknown";
                let isMainNav = false;
                try{
                    isMainNav = req.isNavigationRequest() && req.frame() === page.mainFrame();
                } catch(ex2){
                }
                const reqUrl = String(req.url() || "");
                const keepFailure = isMainNav || isLikelyLoginUrl(reqUrl);
                if (!keepFailure){
                    return;
                }
                const rec = {
                    url: req.url(),
                    method: req.method(),
                    resourceType: req.resourceType(),
                    errorText: errText,
                    mainFrameNavigation: isMainNav
                };
                pushLimited(loginFailedRequests, rec, 12);
                if (isMainNav || !String(errText || "").toLowerCase().includes("err_aborted")){
                    console.log(`[MYDEBUG] [login failed request] url=${req.url()} method=${req.method()} resourceType=${req.resourceType()} mainFrameNav=${isMainNav} error=${errText}`);
                }
            } catch(ex){
            }
        };
        const loginResponseHandler = (resp) => {
            try{
                const req = resp.request();
                if (req && req.isNavigationRequest && req.isNavigationRequest() && req.frame() === page.mainFrame()){
                    const h = resp.headers ? resp.headers() : {};
                    const locationHeader = h && (h.location || h.Location) ? (h.location || h.Location) : "";
                    const setCookieHeader = h && (h["set-cookie"] || h["Set-Cookie"]) ? (h["set-cookie"] || h["Set-Cookie"]) : "";
                    const rec = {
                        url: resp.url(),
                        status: resp.status(),
                        location: locationHeader
                    };
                    pushLimited(loginMainFrameResponses, rec, 12);
                    if (resp.status() >= 300 || isLikelyLoginUrl(resp.url())){
                        console.log(`[MYDEBUG] [login response] nav response: status=${resp.status()} url=${resp.url()} location=${locationHeader || "-"}`);
                        if (resp.status() >= 300){
                            console.log(`[MYDEBUG] [login response] nav redirect headers: set-cookie=${setCookieHeader ? "PRESENT" : "MISSING"} content-type=${h["content-type"] || "-"}`);
                        }
                    }
                }
                const respUrl = String(resp.url() || "");
                if (respUrl.includes("action=process") || respUrl.includes("userprocess.php")){
                    const h = resp.headers ? resp.headers() : {};
                    const locationHeader = h && (h.location || h.Location) ? (h.location || h.Location) : "";
                    const setCookieHeader = h && (h["set-cookie"] || h["Set-Cookie"]) ? (h["set-cookie"] || h["Set-Cookie"]) : "";
                    console.log(`[MYDEBUG] [login process response] status=${resp.status()} url=${respUrl} location=${locationHeader || "-"}`);
                    console.log(`[MYDEBUG] [login process response] set-cookie=${setCookieHeader ? "PRESENT" : "MISSING"} content-type=${h["content-type"] || "-"}`);
                }
            } catch(ex){
            }
        };
        const cleanupLoginListeners = () => {
            if (attachInterceptor){
                try{ page.removeListener('request', interceptLoginRequest); } catch(e){}
            }
            try{ page.removeListener('request', loginRequestHandler); } catch(e){}
            try{ page.removeListener('requestfailed', loginRequestFailedHandler); } catch(e){}
            try{ page.removeListener('response', loginResponseHandler); } catch(e){}
        };
        const failLogin = async (reason, err=null) => {
            cleanupLoginListeners();
            if (err){
                throw err;
            }
            throw new Error(reason);
        };
        page.on('requestfailed', loginRequestFailedHandler);
        page.on('response', loginResponseHandler);
        page.on('request', loginRequestHandler);

        if (attachInterceptor){
            try{
                await page.setRequestInterception(true);
            } catch(ex){
                console.log(`[MYDEBUG] setRequestInterception(true) failed before login intercept: ${ex && ex.message ? ex.message : ex}`);
                attachInterceptor = false;
            }
        }
        if (attachInterceptor){
            page.on('request', interceptLoginRequest);
        }

        console.log("[Login] REQUESTING URL ", gotourl.href);

        //const response = await page.goto(gotourl, {waitUntil:"networkidle2"});
        const maskedUsername = String(loginData["usernameValue"] || "");
        const extraSelectorSummary = extraLoginFields.length > 0 ? extraLoginFields.map(field => `${field.index}:${field.selector}`).join("|") : "-";
        const extraValueLengthSummary = extraLoginFields.length > 0 ? extraLoginFields.map(field => `${field.index}:${field.value.length}`).join("|") : "-";
        console.log(`[MYDEBUG] Login config summary: form_url=${loginData["form_url"]}, method=${loginData["method"]}, submitType=${loginData["submitType"]}, usernameSelector=${loginData["usernameSelector"]}, passwordSelector=${loginData["passwordSelector"]}, extraSelectors=${extraSelectorSummary}, form_selector=${loginData["form_selector"]}, form_submit_selector=${loginData["form_submit_selector"]}, loginStartSelector=${loginData["loginStartSelector"]}, positiveLoginMessage=${loginData["positiveLoginMessage"]}`);
        console.log(`[MYDEBUG] Login value summary: usernameLength=${maskedUsername.length}, passwordLength=${String(loginData["passwordValue"] || "").length}, extraValueLengths=${extraValueLengthSummary}`);
        console.log(`[MYDEBUG] Navigating to login URL: ${gotourl.href}`);
        self.usernameValue = loginData["usernameValue"];
        self.passwordValue = loginData["passwordValue"];
        let navTimeoutMs = 8000;
        try{
            if (loginData && typeof loginData === "object"){
                let v = loginData["nav_timeout_ms"];
                if (typeof v === "undefined"){
                    v = loginData["login_timeout_ms"];
                }
                if (typeof v === "undefined"){
                    v = loginData["navigation_timeout_ms"];
                }
                if (typeof v === "string" || typeof v === "number"){
                    let n = parseInt(v, 10);
                    if (!Number.isNaN(n) && n > 0){
                        navTimeoutMs = n;
                    }
                }
            }
        } catch(ex){
        }
        if (navTimeoutMs < 1000){
            navTimeoutMs = 1000;
        }
        if (navTimeoutMs > 30000){
            navTimeoutMs = 30000;
        }
        let response = null;
        try{
            // Keep login page navigation behavior aligned with request_crawler_bak for stability.
            response = await page.goto(gotourl.href, {
                waitUntil: 'networkidle2',
                timeout: navTimeoutMs
            });
        } catch(ex){
            console.log(`[WC] Login navigation failed url=${gotourl.href}`);
            console.log(ex && ex.message ? ex.message : ex);
            try{
                console.log(`[MYDEBUG] Login navigation fail currentUrl=${await page.url()} title=${await page.title()}`);
                const cks = await page.cookies();
                console.log(`[MYDEBUG] Login navigation fail cookies=${cks.map(c => `${c.name}=${c.value}`).join("; ")}`);
            } catch(exdbg){
            }
            try{
                await Promise.race([
                    page.evaluate(() => { try { window.stop(); } catch(e) {} }),
                    sleepg(500),
                ]);
            } catch(ex2){
            }
            await failLogin("login_navigation_failed", ex);
        }
        let responseStatus = 0;
        try{
            responseStatus = response ? response.status() : 0;
        } catch(ex){
            responseStatus = 0;
        }
        console.log(`[DEBUG] Navigation completed, status: ${responseStatus}`);
        await page.waitForTimeout(3000);
        const loginDialogMessages = [];
        page.on('dialog', async dialog => {
            const dmsg = dialog.message();
            loginDialogMessages.push(dmsg);
            if (loginDialogMessages.length > 10){
                loginDialogMessages.shift();
            }
            console.log(`[WC] Dismissing LOGIN Message: ${dmsg}`);
            await dialog.dismiss();
        });
        console.log(`[Login] URL GOTO'ed `);
        
        try {
            if (loginData["usernameSelector"] || loginData["passwordSelector"]){
                const fillLoginField = async (selector, value, label) => {
                    console.log(`[MYDEBUG] Filling ${label}`);
                    await page.focus(selector);
                    await page.keyboard.type(value, {delay:100});
                };

                console.log(`[MYDEBUG] Waiting for login form elements...`);
                if (loginData["usernameSelector"]) {
                    await page.waitForSelector(loginData["usernameSelector"], { 
                        timeout: 10000 
                    });
                    console.log(`[DEBUG] Username selector found: ${loginData["usernameSelector"]}`);
                }

                await page.waitForSelector(loginData["passwordSelector"], { 
                    timeout: 10000 
                });
                console.log(`[DEBUG] Password selector found: ${loginData["passwordSelector"]}`);

                if (loginData["form_submit_selector"]) {
                    await page.waitForSelector(loginData["form_submit_selector"], { 
                        timeout: 10000 
                    });
                    console.log(`[DEBUG] Submit selector found: ${loginData["form_submit_selector"]}`);
                }
                for (const extraField of extraLoginFields){
                    await page.waitForSelector(extraField.selector, {
                        timeout: 10000
                    });
                    console.log(`[DEBUG] Extra selector found (${extraField.index}): ${extraField.selector}`);
                }

                await page.keyboard.press("Escape");
                await page.keyboard.press("Escape");
                
                if (loginData["loginStartSelector"]){
                    let p = await page.$(loginData["loginStartSelector"])
                    console.log(`[MYDEBUG] Clicking loginStartSelector: ${loginData["loginStartSelector"]} (found=${!!p})`);
                    await p.click();
                    await(sleepg(100));
                }
                // if (loginData["usernameSelector"]) {
                //     await page.focus(loginData["usernameSelector"]);
                //     await page.keyboard.type(loginData["usernameValue"], {delay:100});
                // }
                // await page.focus(loginData["passwordSelector"]);
                // await page.keyboard.type( loginData["passwordValue"], {delay:100});
                if (loginData["usernameSelector"]) {
                    await fillLoginField(loginData["usernameSelector"], String(loginData["usernameValue"] || ""), "username");
                }
                for (const extraField of extraLoginFields){
                    await fillLoginField(extraField.selector, extraField.value, `extra field ${extraField.index}`);
                }

                await fillLoginField(loginData["passwordSelector"], String(loginData["passwordValue"] || ""), "password");
                const element = await page.$(loginData["passwordSelector"]);
                //const text = await (await element.getProperty('value')).jsonValue();
                try{
                    const autoRemember = await page.evaluate((usernameSelector, passwordSelector, submitSelector) => {
                        function q(sel) {
                            try { return sel ? document.querySelector(sel) : null; } catch (e) { return null; }
                        }
                        function text(v) {
                            return (v || "").toString().toLowerCase();
                        }
                        function uniq(arr) {
                            const out = [];
                            const seen = {};
                            for (let i = 0; i < arr.length; i++) {
                                const k = arr[i];
                                if (!k || seen[k]) continue;
                                seen[k] = true;
                                out.push(k);
                            }
                            return out;
                        }
                        function getForm() {
                            let el = q(passwordSelector) || q(usernameSelector) || q(submitSelector);
                            if (el && el.closest) {
                                const f = el.closest("form");
                                if (f) return f;
                            }
                            const fallback = document.querySelector("form input[type='password']");
                            if (fallback && fallback.closest) {
                                const f2 = fallback.closest("form");
                                if (f2) return f2;
                            }
                            return document.querySelector("form");
                        }
                        function scoreCheckbox(cb) {
                            const name = text(cb.getAttribute("name"));
                            const id = text(cb.getAttribute("id"));
                            const cls = text(cb.getAttribute("class"));
                            const value = text(cb.value);
                            const aria = text(cb.getAttribute("aria-label"));
                            const title = text(cb.getAttribute("title"));
                            const dataRole = text(cb.getAttribute("data-role"));
                            let labelText = "";
                            if (id) {
                                const lb = document.querySelector("label[for='" + id.replace(/'/g, "\\'") + "']");
                                if (lb) labelText += " " + text(lb.textContent);
                            }
                            const parentLabel = cb.closest ? cb.closest("label") : null;
                            if (parentLabel) labelText += " " + text(parentLabel.textContent);
                            const parentText = cb.parentElement ? text(cb.parentElement.textContent) : "";

                            const hay = [name, id, cls, value, aria, title, dataRole, labelText, parentText].join(" ");
                            const compact = hay.replace(/[^a-z0-9]+/g, "");

                            const strongKeys = [
                                "remember", "rememberme", "remember_me", "remember-login", "keepme",
                                "keeplogged", "staysigned", "persistentlogin", "autologin",
                                "saveid", "saveuser", "sublogin"
                            ];
                            const weakKeys = [
                                "keep", "stay", "signed", "signin", "sign-in", "login", "persist", "session", "trust"
                            ];
                            const negativeKeys = [
                                "terms", "policy", "privacy", "newsletter", "subscribe", "marketing",
                                "captcha", "robot", "showpassword", "show-pass", "show_pass", "2fa", "otp", "mfa"
                            ];

                            let score = 0;
                            for (let i = 0; i < strongKeys.length; i++) {
                                const k = strongKeys[i];
                                if (hay.indexOf(k) > -1 || compact.indexOf(k.replace(/[^a-z0-9]/g, "")) > -1) score += 4;
                            }
                            for (let i = 0; i < weakKeys.length; i++) {
                                const k = weakKeys[i];
                                if (hay.indexOf(k) > -1) score += 1;
                            }
                            for (let i = 0; i < negativeKeys.length; i++) {
                                const k = negativeKeys[i];
                                if (hay.indexOf(k) > -1) score -= 4;
                            }

                            return {
                                score: score,
                                name: cb.getAttribute("name") || "",
                                id: cb.getAttribute("id") || "",
                                checked: !!cb.checked,
                                disabled: !!cb.disabled
                            };
                        }

                        const form = getForm();
                        if (!form) {
                            return { foundForm: false, checkedNames: [], candidates: [] };
                        }

                        const checkboxes = Array.prototype.slice.call(form.querySelectorAll("input[type='checkbox']"));
                        const candidates = [];
                        const checkedNames = [];
                        for (let i = 0; i < checkboxes.length; i++) {
                            const cb = checkboxes[i];
                            const meta = scoreCheckbox(cb);
                            candidates.push(meta);
                            if (meta.disabled) continue;
                            if (meta.checked) continue;
                            if (meta.score < 2) continue;
                            cb.checked = true;
                            try { cb.dispatchEvent(new Event("input", { bubbles: true })); } catch (e) {}
                            try { cb.dispatchEvent(new Event("change", { bubbles: true })); } catch (e) {}
                            checkedNames.push(meta.name || meta.id || "checkbox#" + i);
                        }
                        return {
                            foundForm: true,
                            checkedNames: uniq(checkedNames),
                            candidates: candidates
                        };
                    }, loginData["usernameSelector"], loginData["passwordSelector"], loginData["form_submit_selector"]);
                    console.log(`[MYDEBUG] Auto remember checkbox: formFound=${autoRemember.foundForm} checkedCount=${(autoRemember.checkedNames || []).length} checked=${JSON.stringify(autoRemember.checkedNames || [])}`);
                    if (autoRemember.candidates && autoRemember.candidates.length > 0){
                        const sorted = autoRemember.candidates
                            .slice(0)
                            .sort((a, b) => (b.score || 0) - (a.score || 0))
                            .slice(0, 5);
                        console.log(`[MYDEBUG] Auto remember candidates(top): ${JSON.stringify(sorted)}`);
                    } else {
                        console.log(`[MYDEBUG] Auto remember candidates(top): []`);
                    }
                } catch(ex){
                    console.log(`[MYDEBUG] Auto remember checkbox failed: ${ex && ex.message ? ex.message : ex}`);
                }
                try{
                    let usernameTypedLen = -1;
                    let passwordTypedLen = -1;
                    const extraTypedLens = [];
                    if (loginData["usernameSelector"]){
                        usernameTypedLen = await page.$eval(loginData["usernameSelector"], el => (el && typeof el.value === "string") ? el.value.length : -1);
                    }
                    for (const extraField of extraLoginFields){
                        const extraTypedLen = await page.$eval(extraField.selector, el => (el && typeof el.value === "string") ? el.value.length : -1);
                        extraTypedLens.push(`${extraField.index}:${extraTypedLen}`);
                    }
                    passwordTypedLen = await page.$eval(loginData["passwordSelector"], el => (el && typeof el.value === "string") ? el.value.length : -1);
                    console.log(`[MYDEBUG] Input value length check: usernameLen=${usernameTypedLen}, passwordLen=${passwordTypedLen}, extraLens=${extraTypedLens.length > 0 ? extraTypedLens.join("|") : "-"}`);
                } catch(ex){
                    console.log(`[MYDEBUG] Input value length check failed: ${ex && ex.message ? ex.message : ex}`);
                }
                try{
                    const formSnapshot = await page.evaluate((usernameSelector, passwordSelector) => {
                        const q = (s) => {
                            try { return s ? document.querySelector(s) : null; } catch (e) { return null; }
                        };
                        const u = q(usernameSelector);
                        const p = q(passwordSelector);
                        const base = p || u;
                        let form = null;
                        if (base && typeof base.closest === "function"){
                            form = base.closest("form");
                        }
                        if (!form && p && p.form){
                            form = p.form;
                        }
                        if (!form && u && u.form){
                            form = u.form;
                        }
                        const out = {
                            foundForm: !!form,
                            action: "",
                            method: "",
                            fields: [],
                            hasRemember: false,
                            hasSublogin: false
                        };
                        if (!form){
                            return out;
                        }
                        out.action = form.getAttribute("action") || "";
                        out.method = (form.getAttribute("method") || "").toUpperCase();
                        const els = form.querySelectorAll("input,select,textarea,button");
                        for (const el of els){
                            const tag = (el.tagName || "").toLowerCase();
                            const type = ((el.getAttribute("type") || tag) + "").toLowerCase();
                            const name = (el.getAttribute("name") || "").trim();
                            if (!name){
                                continue;
                            }
                            let value = "";
                            if (type === "checkbox" || type === "radio"){
                                value = el.checked ? (el.value || "on") : "";
                            } else {
                                value = el.value || "";
                            }
                            if (name === "pass" || name === "password"){
                                value = `<len:${value.length}>`;
                            }
                            if (name.toLowerCase() === "remember"){
                                out.hasRemember = true;
                            }
                            if (name.toLowerCase() === "sublogin"){
                                out.hasSublogin = true;
                            }
                            out.fields.push({ name, type, value });
                        }
                        return out;
                    }, loginData["usernameSelector"], loginData["passwordSelector"]);
                    console.log(`[MYDEBUG] Login form snapshot: action=${formSnapshot.action || "-"} method=${formSnapshot.method || "-"} foundForm=${formSnapshot.foundForm} hasRemember=${formSnapshot.hasRemember} hasSublogin=${formSnapshot.hasSublogin}`);
                    console.log(`[MYDEBUG] Login form fields: ${JSON.stringify(formSnapshot.fields)}`);
                } catch(ex){
                    console.log(`[MYDEBUG] Login form snapshot failed: ${ex && ex.message ? ex.message : ex}`);
                }

                //await page.screenshot({path: '/p/tmp/screenshot-pre-login.png', type:"png"});

                // let submitType = loginData["submitType"].toLowerCase();
                // let navwait =  page.waitForNavigation({waitUntil:"load"});
                // if (submitType === "submit"){
                //     const inputElement = await page.$('input[type=submit]');
                //     await inputElement.click();
                // } else if (submitType === "enter"){
                //     //console.log("\nPRESSING ENTERE\n");
                //     await Promise.all([page.keyboard.type("\n"), page.waitForNavigation({timeout: 10000, waitUntil:'networkidle2'})])

                // } else if (submitType === "click") {
                //     //await page.keyboard.type("");
                //     console.log("submitting form");
                //     const formElement = await page.$(loginData["form_selector"]);
                //     const inputElement = await formElement.$(loginData["form_submit_selector"]);
                //     inputElement.disabled = false
                //     console.log("input element = ", inputElement),
                //     await Promise.all([page.evaluate("$('#loginButton').disabled = false;$('#loginButton').click()"),
                //         await inputElement.click(),
                //         page.waitForNavigation({timeout: 5000, waitUntil:'networkidle2'})]);

                // }
                let submitType = String(loginData["submitType"] || "enter").toLowerCase();
                console.log(`[MYDEBUG] Using submit type: ${submitType}`);

                let navTimedOutAfterSubmit = false;
                if (submitType === "submit"){
                    console.log(`[MYDEBUG] Submit mode=submit, click input[type=submit]`);
                    const inputElement = await page.$('input[type=submit]');
                    if (!inputElement){
                        console.log(`[MYDEBUG] input[type=submit] not found`);
                        throw new Error("submit_input_not_found");
                    }
                    await inputElement.click();
                } else if (submitType === "enter"){
                    console.log(`[MYDEBUG] Submit mode=enter, sending newline + waiting navigation`);
                    console.log(`[MYDEBUG] URL before submit: ${await page.url()}`);
                    let navResp = null;
                    try{
                        navResp = await Promise.all([
                            page.keyboard.type("\n"),
                            page.waitForNavigation({timeout: 10000, waitUntil:'networkidle2'})
                        ]);
                    } catch (navEx){
                        if (navEx && navEx.name === "TimeoutError"){
                            navTimedOutAfterSubmit = true;
                            console.log(`[MYDEBUG] waitForNavigation timeout after submitType=enter, will verify login state before failing`);
                        } else {
                            throw navEx;
                        }
                    }
                    const r = navResp && navResp.length > 1 ? navResp[1] : null;
                    if (r){
                        let rstatus = 0;
                        let rurl = "";
                        try{ rstatus = r.status(); } catch(ex){}
                        try{ rurl = r.url(); } catch(ex){}
                        console.log(`[MYDEBUG] waitForNavigation response: status=${rstatus} url=${rurl}`);
                    } else {
                        console.log(`[MYDEBUG] waitForNavigation response: null`);
                    }
                    console.log(`[MYDEBUG] Navigation after login completed, URL now: ${await page.url()}`);
                } else if (submitType === "click") {
                    console.log(`[MYDEBUG] Submit mode=click, form_selector=${loginData["form_selector"]}, form_submit_selector=${loginData["form_submit_selector"]}`);
                    const formElement = await page.$(loginData["form_selector"]);
                    if (!formElement){
                        console.log(`[MYDEBUG] form element not found by selector: ${loginData["form_selector"]}`);
                        throw new Error("form_selector_not_found");
                    }
                    const inputElement = await formElement.$(loginData["form_submit_selector"]);
                    if (!inputElement){
                        console.log(`[MYDEBUG] submit element not found inside form: ${loginData["form_submit_selector"]}`);
                        throw new Error("form_submit_selector_not_found");
                    }
                    inputElement.disabled = false;
                    try{
                        await Promise.all([
                            page.evaluate("$('#loginButton').disabled = false;$('#loginButton').click()"),
                            inputElement.click(),
                            page.waitForNavigation({timeout: 5000, waitUntil:'networkidle2'})
                        ]);
                    } catch (navEx){
                        if (navEx && navEx.name === "TimeoutError"){
                            navTimedOutAfterSubmit = true;
                            console.log(`[MYDEBUG] waitForNavigation timeout after submitType=click, will verify login state before failing`);
                        } else {
                            throw navEx;
                        }
                    }
                    console.log(`[MYDEBUG] Navigation after login completed, URL now: ${await page.url()}`);
                } else {
                    console.log(`[MYDEBUG] Unknown submitType '${submitType}', fallback to enter`);
                    console.log(`[MYDEBUG] URL before submit: ${await page.url()}`);
                    try{
                        await Promise.all([
                            page.keyboard.type("\n"),
                            page.waitForNavigation({timeout: 10000, waitUntil:'networkidle2'})
                        ]);
                    } catch (navEx){
                        if (navEx && navEx.name === "TimeoutError"){
                            navTimedOutAfterSubmit = true;
                            console.log(`[MYDEBUG] waitForNavigation timeout after submitType fallback, will verify login state before failing`);
                        } else {
                            throw navEx;
                        }
                    }
                    console.log(`[MYDEBUG] Navigation after login completed, URL now: ${await page.url()}`);
                }
                if (navTimedOutAfterSubmit){
                    let navLikelySucceeded = false;
                    const positiveLoginMessage = String(loginData["positiveLoginMessage"] || "");
                    for (let verifyIdx = 1; !navLikelySucceeded && verifyIdx <= 3; verifyIdx++){
                        if (verifyIdx > 1){
                            await page.waitForTimeout(1000);
                        }
                        try{
                            const curUrlAfterTimeout = await page.url();
                            const cookieAfterTimeout = await page.cookies();
                            const hasCookiesNow = Array.isArray(cookieAfterTimeout) && cookieAfterTimeout.length > 0;
                            const bodyAfterTimeout = await page.content();
                            const hasPositiveMessageNow = positiveLoginMessage.length > 0 && bodyAfterTimeout.indexOf(positiveLoginMessage) > -1;
                            navLikelySucceeded = hasPositiveMessageNow && hasCookiesNow;
                            console.log(`[MYDEBUG] Post-timeout login verification attempt ${verifyIdx}: url=${curUrlAfterTimeout} cookies=${cookieAfterTimeout.length} hasPositiveMessage=${hasPositiveMessageNow} accepted=${navLikelySucceeded}`);
                        } catch(ex){
                            console.log(`[MYDEBUG] Post-timeout login verification attempt ${verifyIdx} failed: ${ex && ex.message ? ex.message : ex}`);
                        }
                    }
                    if (!navLikelySucceeded){
                        throw new Error("login_navigation_timeout_unverified");
                    }
                }
            } else {
                 console.log(`No login b/c usernameSelector config value is empty`);
            }



        } catch (err){
            console.log("CRITICAL ERROR: login failed");
            try{
                console.log(`[MYDEBUG] Current URL on login error: ${await page.url()}`);
                console.log(`[MYDEBUG] Current title on login error: ${await page.title()}`);
                const cookiesNow = await page.cookies();
                console.log(`[MYDEBUG] Current cookies on login error: ${cookiesNow.map(c => `${c.name}=${c.value}`).join("; ") || "-"}`);
                const bodyNow = await page.content();
                const bodySnippet = String(bodyNow || "").replace(/\s+/g, " ").slice(0, 500);
                console.log(`[MYDEBUG] Body snippet on login error: ${bodySnippet}`);
                const visibility = await page.evaluate((usernameSelector, passwordSelector, submitSelector) => {
                    const pick = (sel) => {
                        try{
                            if (!sel){ return {exists:false, visible:false, valueLen:-1}; }
                            const el = document.querySelector(sel);
                            if (!el){ return {exists:false, visible:false, valueLen:-1}; }
                            const style = window.getComputedStyle(el);
                            const rect = el.getBoundingClientRect();
                            const value = typeof el.value === "string" ? el.value.length : -1;
                            return {
                                exists:true,
                                visible: style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0,
                                valueLen:value
                            };
                        } catch(ex){
                            return {exists:false, visible:false, valueLen:-1};
                        }
                    };
                    return {
                        username: pick(usernameSelector),
                        password: pick(passwordSelector),
                        submit: pick(submitSelector)
                    };
                }, loginData["usernameSelector"], loginData["passwordSelector"], loginData["form_submit_selector"]);
                console.log(`[MYDEBUG] Login form visibility on error: ${JSON.stringify(visibility)}`);
            } catch(ex){
            }
            if (loginMainFrameResponses.length > 0){
                console.log(`[MYDEBUG] Main-frame navigation summary: count=${loginMainFrameResponses.length} last=${JSON.stringify(loginMainFrameResponses[loginMainFrameResponses.length - 1])}`);
            }
            if (loginFailedRequests.length > 0){
                console.log(`[MYDEBUG] Failed requests summary: count=${loginFailedRequests.length} last=${JSON.stringify(loginFailedRequests[loginFailedRequests.length - 1])}`);
            }
            console.log(err);
            console.log(err.stack);
            await failLogin("login_submit_failed", err);
        }

        try{
            console.log(`[MYDEBUG] Login completed, current URL: ${await page.url()}`);
            console.log(`[MYDEBUG] Page title: ${await page.title()}`);
            console.log(`[MYDEBUG] Screenshot saved for inspection`);

            const pageCookies = await page.cookies();
            const sessionCookie = pageCookies.find(c => c.name.toLowerCase().includes('sid') || c.name.toLowerCase().includes('sess'));
            console.log(`[MYDEBUG] Session cookie check: ${sessionCookie ? `${sessionCookie.name}=EXISTS` : 'MISSING'}`);
            if (loginMainFrameResponses.length > 0){
                console.log(`[MYDEBUG] Main-frame navigation summary: count=${loginMainFrameResponses.length} last=${JSON.stringify(loginMainFrameResponses[loginMainFrameResponses.length - 1])}`);
            }
            if (loginFailedRequests.length > 0){
                console.log(`[MYDEBUG] Failed requests summary: count=${loginFailedRequests.length} last=${JSON.stringify(loginFailedRequests[loginFailedRequests.length - 1])}`);
            }
            const currentLoginUrl = await page.url();
            const redirectResponses = loginMainFrameResponses.filter(r => r.status >= 300 && r.status < 400);
            const lastRedirect = redirectResponses.length > 0 ? redirectResponses[redirectResponses.length - 1] : null;
            const hasRedirect = !!lastRedirect;
            const redirectLocation = lastRedirect && lastRedirect.location ? String(lastRedirect.location) : "";
            const redirectedToPatient = redirectLocation.toLowerCase().includes("patient/patient.php");
            const redirectedToIndex = redirectLocation.toLowerCase().includes("/index.php");
            const hasMainFrameErrFailed = loginFailedRequests.some(r =>
                r.mainFrameNavigation && String(r.errorText || "").toLowerCase().includes("err_failed")
            );
            const hasWrongInputDialog = loginDialogMessages.some(m => String(m).toLowerCase().includes("wrong input"));
            console.log(`[MYDEBUG] Login redirect summary: has3xxRedirect=${hasRedirect}, redirectLocation=${redirectLocation || "-"}, redirectedToPatient=${redirectedToPatient}, currentUrl=${currentLoginUrl}`);
            console.log(`[MYDEBUG] Login dialog summary: count=${loginDialogMessages.length}, hasWrongInputDialog=${hasWrongInputDialog}`);
            if (hasRedirect && hasMainFrameErrFailed && redirectLocation){
                if (redirectedToPatient){
                    console.log(`[MYDEBUG] Login verdict: credentials accepted (3xx to patient.php), but redirected document request failed (ERR_FAILED).`);
                } else {
                    console.log(`[MYDEBUG] Login verdict: got 3xx redirect, but redirected document request failed (ERR_FAILED).`);
                }
                try{
                    const retryUrl = new URL(redirectLocation, gotourl.href).href;
                    console.log(`[MYDEBUG] Retry loading redirected page once: ${retryUrl}`);
                    const retryResp = await page.goto(retryUrl, {
                        waitUntil: 'networkidle2',
                        timeout: 15000
                    });
                    let retryStatus = 0;
                    let retryRespUrl = retryUrl;
                    try{ retryStatus = retryResp ? retryResp.status() : 0; } catch(ex){}
                    try{ retryRespUrl = retryResp && retryResp.url ? retryResp.url() : retryRespUrl; } catch(ex){}
                    console.log(`[MYDEBUG] Retry navigation result: status=${retryStatus} responseUrl=${retryRespUrl} currentUrl=${await page.url()}`);
                } catch(retryEx){
                    console.log(`[MYDEBUG] Retry navigation failed: ${retryEx && retryEx.message ? retryEx.message : retryEx}`);
                }
            } else if (redirectedToPatient){
                console.log(`[MYDEBUG] Login verdict: credentials likely accepted (3xx to patient.php).`);
            } else if (hasWrongInputDialog || (redirectedToIndex && hasMainFrameErrFailed)){
                if (hasWrongInputDialog){
                    console.log(`[MYDEBUG] Login verdict: likely login failed (wrong input dialog detected).`);
                } else {
                    console.log(`[MYDEBUG] Login verdict: likely login failed or session not established on index.php.`);
                }
            } else {
                console.log(`[MYDEBUG] Login verdict: inconclusive, check redirect/failure logs above.`);
            }

            // Some apps (e.g. rconfig-like flows) first 302 back to login page and only on next request
            // redirect to dashboard after session is persisted. Probe one extra GET when we already have session cookie.
            try{
                const curUrlObj = new URL(currentLoginUrl, gotourl.href);
                const loginUrlObj = new URL(gotourl.href);
                const curPath = (curUrlObj.pathname || "").toLowerCase();
                const loginPath = (loginUrlObj.pathname || "").toLowerCase();
                const sameOrigin = (curUrlObj.origin === loginUrlObj.origin);
                const sameAsLoginPath = sameOrigin && curPath === loginPath;
                const looksLikeLoginPath = sameOrigin && (curPath.includes("/login.php") || curPath.endsWith("/login"));
                const redirectBackToLogin = hasRedirect && String(redirectLocation || "").toLowerCase().includes("login.php");
                const shouldProbe = !!sessionCookie && (sameAsLoginPath || looksLikeLoginPath || redirectBackToLogin);
                console.log(`[MYDEBUG] Login probe condition: sessionCookie=${!!sessionCookie} sameAsLoginPath=${sameAsLoginPath} looksLikeLoginPath=${looksLikeLoginPath} redirectBackToLogin=${redirectBackToLogin} shouldProbe=${shouldProbe}`);
                if (shouldProbe){
                    console.log(`[MYDEBUG] Login probe: probing login URL once more for post-auth redirect`);
                    const probeResp = await page.goto(gotourl.href, {
                        waitUntil: 'networkidle2',
                        timeout: 15000
                    });
                    let probeStatus = 0;
                    let probeRespUrl = gotourl.href;
                    try{ probeStatus = probeResp ? probeResp.status() : 0; } catch(ex){}
                    try{ probeRespUrl = probeResp && probeResp.url ? probeResp.url() : probeRespUrl; } catch(ex){}
                    console.log(`[MYDEBUG] Login probe result: status=${probeStatus} responseUrl=${probeRespUrl} currentUrl=${await page.url()}`);
                }
            } catch(ex){
                console.log(`[MYDEBUG] Login probe failed: ${ex && ex.message ? ex.message : ex}`);
            }

            const bodyResponse = await page.content();

        let responseStatusCode = 0;
        try{
            responseStatusCode = response ? response.status() : 0;
        } catch(ex){
            responseStatusCode = 0;
        }

        //console.log(bodyResponse);
        //console.log("POSI IS ", loginData["positiveLoginMessage"]);
        // if (bodyResponse.indexOf(loginData["positiveLoginMessage"]) === -1){
        //     console.log(bodyResponse);
        //     console.log("\nERROR ERROR ERROR ERROR  LOGIN FAILED TO COMPLETE, didn't find expected message ERROR ERROR ERROR ");
        //     process.exit(38);
        // }
        const positiveLoginMessage = String(loginData["positiveLoginMessage"] || "");
        console.log(`[MYDEBUG] Checking for positive login message: ${positiveLoginMessage}`);
        let positiveCheckBody = bodyResponse;
        let positiveFound = positiveLoginMessage.length > 0 && positiveCheckBody.indexOf(positiveLoginMessage) > -1;
        for (let attemptIdx = 1; !positiveFound && attemptIdx <= 3; attemptIdx++){
            let waitMs = 0;
            if (attemptIdx === 2){ waitMs = 1000; }
            if (attemptIdx === 3){ waitMs = 5000; }
            if (waitMs > 0){
                console.log(`[MYDEBUG] Positive message check attempt ${attemptIdx}: waiting ${waitMs}ms before retry`);
                await page.waitForTimeout(waitMs);
                positiveCheckBody = await page.content();
            }
            positiveFound = positiveLoginMessage.length > 0 && positiveCheckBody.indexOf(positiveLoginMessage) > -1;
            if (!positiveFound){
                let readyState = "unknown";
                try{
                    readyState = await page.evaluate(() => document.readyState);
                } catch(ex){
                }
                console.log(`[MYDEBUG] Positive message miss on attempt ${attemptIdx}: attachInterceptor=${!!attachInterceptor} readyState=${readyState} url=${await page.url()} title=${await page.title()} bodyLen=${positiveCheckBody.length}`);
            }
        }
        if (!positiveFound){
            console.log(`[MYDEBUG] Positive login message not found after 3 attempts: ${positiveLoginMessage}`);
            try{
                const usernameVisible = loginData["usernameSelector"] ? !!(await page.$(loginData["usernameSelector"])) : false;
                const passwordVisible = loginData["passwordSelector"] ? !!(await page.$(loginData["passwordSelector"])) : false;
                console.log(`[MYDEBUG] Login form visibility after submit: usernameSelector=${usernameVisible} passwordSelector=${passwordVisible}`);
            } catch(ex){
                console.log(`[MYDEBUG] Login form visibility check failed: ${ex && ex.message ? ex.message : ex}`);
            }
            try{
                const lowerBody = String(positiveCheckBody || "").toLowerCase();
                const hints = ["wrong", "invalid", "error", "failed", "install", "preinstall", "not found"];
                const matched = hints.filter(h => lowerBody.indexOf(h) > -1);
                console.log(`[MYDEBUG] Login failure keyword hints: ${matched.length > 0 ? matched.join(",") : "-"}`);
            } catch(ex){
            }
            console.log(`[MYDEBUG] Page content snippet: ${positiveCheckBody.substring(0, 120)}...`);
            console.log("\nERROR ERROR ERROR ERROR  LOGIN FAILED TO COMPLETE, didn't find expected message ERROR ERROR ERROR ");
            process.exit(38);
        } else {
            console.log(`[MYDEBUG] Positive login message found!`);
        }
        if (responseStatusCode >= 400 && responseStatusCode < 600){
            let rurl = gotourl.href;
            try{
                if (response && response.url){
                    rurl = response.url();
                }
            } catch(ex){
            }
            console.log(`[WC] Response status ${responseStatusCode} during login for ${rurl}`);
            console.log(`[MYDEBUG] Ignoring login HTTP status because positive login message was confirmed on the final page.`);
        }
        } finally {
            cleanupLoginListeners();
        }

        let cookies = await page.cookies();
        //console.log("Cookies returned are ", cookies);
        let loginPageLanding = await page.url();
        //console.log("\x1b[36mLanding page of login ", loginPageLanding , "");
        let foundRequest = FoundRequest.requestParamFactory(loginPageLanding,"GET", "",{},"targetChanged", self.appData.site_url.href);
        self.requestsAdded += self.appData.addInterestingRequest(foundRequest);

        return cookies
    }

    async addCookiesToPage(loginCookies, cookiestr, page) {

        var cookiesarr = String(cookiestr || "").split(";");
        var cookies_in = [];
        for (let cooky of loginCookies) {
            cookies_in.push(cooky); //["name"] + "=" + cooktest[cooky]["value"] + ";";
        }

        cookiesarr.forEach((cv) => {
            if (cv.length > 2 && cv.search("=") > -1) {
                var cvarr = cv.split("=");
                var cv_name = `${cvarr[0].trim()}`;
                var cv_value = `${cvarr[1].trim()}`;
                cookies_in.push({"name": cv_name, "value": cv_value, url: `${this.appData.site_url.origin}`});

            }
        });
        //console.log("COOKIES", cookies_in);
        for (let cooky of cookies_in) {
            console.log("[\x1b[38;5;5mWC\x1b[0m] Cookie: " + cooky["name"] + "=" + cooky["value"] + "");
            if (cooky["name"] === "token"){
                page.setExtraHTTPHeaders({Authorization:`Bearer ${cooky["value"]}`});
                this.bearer = `Bearer ${cooky["value"]}`;
            }
            this.cookies.push({"name": cooky["name"], "value": cooky["value"]});
            //console.log("COOKIES = ",this.cookies);
        }

        await page.setCookie(...cookies_in);
    }
    hasGremlinResults(){
        return ("grandTotal" in this.gremCounter);
    }
    gremTracker(ltext){

        try {
            this.gremCounter["grandTotal"] = ("grandTotal" in this.gremCounter) ? this.gremCounter["grandTotal"] + 1: 0;
            const { groups: { primaryKey, secKey } } = /gremlin (?<primaryKey>[a-z]*)[ ]*(?<secKey>[a-z]*)/.exec(ltext);
            this.gremCounter[primaryKey] = (primaryKey in this.gremCounter) ? this.gremCounter[primaryKey]: {total:0};
            this.gremCounter[primaryKey]["total"] += 1;
            let combinedKey = `${primaryKey} ${secKey}`;
            this.gremCounter[primaryKey][secKey] = (secKey in this.gremCounter[primaryKey]) ? this.gremCounter[primaryKey][secKey] + 1 : 1;

        } catch (err){
            // skip if no match
        }

    }
    getRoundResults(){
        let total = 0, above = 0, below = 0, equalto = 0;
        for (let key in this.appData.requestsFound) {
            let val = this.appData.requestsFound[key];
            total++;
            equalto += val["attempts"] === this.appData.currentURLRound ? 1 : 0;
            above += val["attempts"] === this.appData.currentURLRound ? 0 : 1;
        }
        return {totalInputs:this.appData.numInputsFound(), totalRequests: total, equaltoRequests: equalto, aboveRequests:above}
    }
    reportResults(){
        let hasShownMessages = false;
        for (let k in this.shownMessages) { hasShownMessages = true; break; }
        if (hasShownMessages) {
            console.log("ERRORS:");
            for (let key in this.shownMessages) {
                let val = this.shownMessages[key];
                let strindex = key.indexOf("\n");
                strindex = strindex === -1 ? key.length : strindex;
                console.log(`\tERROR msg '${key.substring(0, strindex)}' seen ${val} times`);
            }
        }
        if (this.hasGremlinResults()) {
            console.log(this.gremCounter);
        }

        let roundResults = this.getRoundResults();
        console.log(`[WC] Round Results for round ${this.appData.currentURLRound} of ${MAX_NUM_ROUNDS}: Total Inputs :  ${roundResults.totalInputs} Total Requests: ${roundResults.equaltoRequests} of ${roundResults.totalRequests} processed so far`);

    }
    setPageTimer(){
        var self = this;
        const triggerAbortCurrentRequest = () => {
            self.abortCurrentRequest = true;
            self.browser_up = false;
            if (typeof self.abortPromiseResolver === "function"){
                try{
                    self.abortPromiseResolver("stuck_abort");
                } catch(ex){
                }
                self.abortPromiseResolver = null;
            }
        };
        const closeWithTimeout = async (browserObj, timeoutMs) => {
            if (!browserObj || typeof browserObj.close !== "function"){
                return false;
            }
            let timedOut = false;
            try{
                await Promise.race([
                    browserObj.close(),
                    new Promise((resolve) => setTimeout(() => { timedOut = true; resolve(false); }, timeoutMs)),
                ]);
            } catch(ex){
            }
            return !timedOut;
        };
        if (this.pagetimeout){
            console.log("[WC] \x1b[38;5;10mReseting page timer \x1b[0m");
            clearTimeout(this.pagetimeout);
        }
        if (this.pagekilltimeout){
            clearTimeout(this.pagekilltimeout);
        }
        this.pagetimeout = setTimeout(async () => {
            console.log("I think we are STUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK");
            try{
                triggerAbortCurrentRequest();
                self.pagekilltimeout = setTimeout(() => {
                    console.log("[WC] Browser close timeout; force-detach current request and continue next");
                    self.reinitPage = true;
                    triggerAbortCurrentRequest();
                    try{
                        if (self.page && typeof self.page.close === "function"){
                            self.page.close({runBeforeUnload:false}).catch(() => {});
                        }
                    } catch(ex){
                    }
                    try{
                        if (self.browser && typeof self.browser.disconnect === "function"){
                            self.browser.disconnect();
                        }
                    } catch(ex){
                    }
                }, 15000);
                await closeWithTimeout(self.browser, 5000);
                console.log("Broswer should have closed by now");
            } catch (err){
                console.log("\tProblem closing browser after timeout\n");
                console.log(err);
            }
        }, this.actionLoopTimeout*1000 + 6000);
    }
    async start() {
        var self = this;
        if (!SIGINT_HANDLER_INSTALLED){
            SIGINT_HANDLER_INSTALLED = true;
            process.once('SIGINT', function() {
                console.log("[WC] Caught interrupt signal, attempting to exit");
                process.exit(99);
            });
            process.once('SIGTERM', function() {
                console.log("[WC] Caught SIGTERM, attempting to exit");
                process.exit(98);
            });
        }
        async function targetChanged(target){

            try {
                if (!target || typeof target.page !== "function"){
                    return;
                }
                const newPage = await target.page();
                if (!newPage){
                    return;
                }
                if (typeof newPage.target !== "function"){
                    return;
                }
                let newTarget = newPage.target();
                if (!newTarget || typeof newTarget.url !== "function"){
                    return;
                }
                var newurl = newTarget.url();

                let turl = "";
                try{
                    if (typeof target.url === "function"){
                        turl = target.url();
                    }
                } catch(ex){
                    turl = "";
                }
                if (turl !== "" && turl !== self.url.href && turl.startsWith(`${self.appData.site_url.origin}`)) {

                    //console.log(`TARGETED CHANGED from ${self.url.href} to ${target.url()} `);
                    //console.log(target);
                    let foundRequest = FoundRequest.requestParamFactory(turl,"GET", "",{},"targetChanged", self.appData.site_url.href);
                    foundRequest.from = "targetChanged";
                    self.requestsAdded += self.appData.addInterestingRequest(foundRequest);

                    //var tempurl = new URL(newurl);
                    //console.log("target changed -----------------------> ", tempurl.pathname);
                    // tempurl.searchParams.forEach(function (value, key, parent) {
                    //     self.appData.addQueryParam(key, value);
                    //     //console.log("PARAM NAME :::> ", key, value);
                    // });
                } else {  // target is foreign or same url
                    //console.log(`TARGETED CHANGED to SAME ${self.url.href}`);
                    var tempurl = new URL(newurl);
                    //console.log("target changed -----------------------> ", tempurl.pathname);
                    tempurl.searchParams.forEach(function (value, key, parent) {
                        //self.appData.addQueryParam(key, value);
                        //console.log("PARAM NAME :::> ", key, value);
                    });

                    // self.page = await self.browser.newPage();
                    // await self.page.goto(newurl,{waitUntil:"load"});
                    // await self.addCodeExercisersToPage(self.hasGremlinResults());
                }
                //self.page = newPage;
            } catch (e) {
                console.log(`TARGET CHANGED Error: target changed encountered an error`);
                console.log(e.message);
                //await browser.close();
            }

        }

        function pageError (error) {
            let msg = error.message;
            if (msg.length> 50){
                msg = msg.substring(0, 50);
            }
            if (msg in self.shownMessages) {
                if (self.shownMessages[msg] % 1000 === 0) {
                    console.log(msg, ` seen for the ${self.shownMessages[msg]} time`);
                }
                self.shownMessages[msg] += 1;
            } else if (error.message.indexOf("TypeError: Cannot read property 'species' of undefined") > -1) {
                console.log("\x1b[38;5;136mGREMLINS JS Error:\n\t", error.message, "\x1b[0m");
                self.gremlins_error = true;
            } else {
                self.shownMessages[msg] = 1;
                // Avoid printing error.message which might trigger a full object serialization in V8
                // when it is a deeply nested or circular Puppeteer/V8 Error object.
                let safeMessage = error && typeof error.message === 'string' ? error.message : "Unknown Error";
                console.log("\x1b[38;5;136mBrowser JS Error:\n\t", safeMessage, "\x1b[0m");
            }

        }

        function logLimited(key, message, firstLimit=3, every=50) {
            if (!self._limitedLogCounts){
                self._limitedLogCounts = {};
            }
            const nextCount = (self._limitedLogCounts[key] || 0) + 1;
            self._limitedLogCounts[key] = nextCount;
            if (nextCount <= firstLimit || (every > 0 && nextCount % every === 0)){
                if (nextCount <= firstLimit){
                    console.log(message);
                } else {
                    console.log(`${message} (repeat #${nextCount})`);
                }
            }
        }

        function consoleLog (message) {
            if (typeof self._consoleLogWindowStart !== "number"){
                self._consoleLogWindowStart = Date.now();
                self._consoleLogWindowCount = 0;
            }
            let now = Date.now();
            if (now - self._consoleLogWindowStart > 1000){
                self._consoleLogWindowStart = now;
                self._consoleLogWindowCount = 0;
            }
            self._consoleLogWindowCount += 1;
            if (self._consoleLogWindowCount > 50){
                return;
            }

            if (message.text().indexOf("[WC]") > -1) {
                if (message.text().indexOf("lamehorde is done") > -1){
                    console.log(`[\x1b[38;5;136mWC${ENDCOLOR}] Lamehorde completion detected`);
                    self.lamehord_done = true;
                } else {
                    let t = message.text();
                    if (t.length > 500){
                        t = t.slice(0,500);
                    }
                    console.log(t);
                }
            } else if (message.text().startsWith("[WC-URL]")){
                let urlstr = message.text().slice("[WC-URL]".length).trim();
                if (!(urlstr.startsWith("http") || urlstr.startsWith("/") || urlstr.startsWith("./") || urlstr.startsWith("../"))){
                    return;
                }
                console.log(`[WC] puppeteer layer recieved url from browser with urlstr='${urlstr}'`);
                try{
                    self.appData.addValidURLS([urlstr], new URL(self.appData.site_url.href), "ConsleRecvd");
                } catch(ex){
                }
                
            } else if (message.text().search("CW DOCUMENT") === -1 && message.text() !== "JSHandle@node") {
                if (message.text().indexOf("gremlin") > -1){
                    self.gremTracker(message.text());
                } else if (message.text().indexOf("mogwai") > -1){
                    self.gremTracker(message.text());
                } else {
                    // Drop arbitrary page console chatter to keep crawler logs readable.
                    return;
                }
            }
        }


        /**
         * Two phases, in the first, we record and save any relevant request information on local requests.
         * In the second, we attempt to determine if the request should be aborted.
         * @param req
         */
        function processRequest(req){
            // interception does not fire for /#/XXXX changes
            // During bootstrap/main navigation loading, always pass main-frame navigations through.
            // This avoids deadlocks/timeouts caused by request mutation or redirect blocking.
            try{
                if (self.isLoading && req.isNavigationRequest() && req.frame() === self.page.mainFrame()){
                    req.continue();
                    return;
                }
            } catch(ex){
            }

            // Save Request info if we can
            if (req.method() !== "GET" || req.postData() || req.resourceType() === "xhr"){
                //console.log("NONGET: ", req.url(), "method=",req.method(), "restype=", req.resourceType(), "data=", req.postData());
            }
            
            let tempurl = new URL(req.url());
            
            // Joomla com_config protection: drop large config.store POST requests
            // These requests modify the global site config and can take the site offline.
            if (req.method() === 'POST' && tempurl.pathname.includes('index.php') && tempurl.search.includes('option=com_config')) {
                if (tempurl.search.includes('task=config.store') || (req.postData() && req.postData().length > 2000)) {
                    console.log(`\x1b[38;5;1mINTERCEPTED and ABORTED Joomla config modification URL ${req.url()}\x1b[0m`);
                    req.abort();
                    return;
                }
            }

            if (tempurl.pathname.search(/\.css$/) > -1 || tempurl.pathname.search(/\.js$/) > -1) {
                console.log("CSS/JS Request Coming THROUGH!!!!! ", req.url(), "method=",req.method(), "restype=", req.resourceType(), "data=", req.postData());
                req.continue()
                return;
            }
            if (req.url().search(/.*HNAP1/) > -1){
                let re = new RegExp(/<soap:Body>(.*)<\/soap:Body>/);
                if (re.test(req.postData())){
                    let pd_match = re.exec(req.postData());
                    //console.log(`${GREEN}${req.url()} ${pd_match[1]}${ENDCOLOR}`);
                } else {
                    //console.log(`${GREEN}${req.url()} NO SOAP MATCH ${req.postData()} ${ENDCOLOR}`);
                }
            }
            //console.log("Interceptd ", req.url());
            if (self.url.href === req.url()) {
                //not sure why reforming request data for continue here.

                var pdata = {
                    'method': self.method,
                    'postData': self.postData,
                    headers: {
                        ...req.headers(),
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                };

                let foundRequest = FoundRequest.requestObjectFactory(req, self.appData.site_url.href);
                foundRequest.from="InterceptedRequestSelf";

                let allParams = foundRequest.getAllParams();
                for (let pkey in allParams){
                    let pvalue = allParams[pkey];
                    if (typeof pvalue === "object"){
                        pvalue = pvalue.values().next().value;
                    }
                    self.appData.addQueryParam(pkey, pvalue);
                }

                if (self.appData.addInterestingRequest(foundRequest) > 0){
                    self.requestsAdded++;
                }

                if (!self.isLoading){
                    req.respond({status:204});
                    return;
                    //self.reinitPage = true;
                }
                console.log("\x1b[38;5;5mprocessRequest caught to add method and data and continueing \x1b[0m", req.url());
                req.continue(pdata);
               
            } else {

                //self.appData.addInterestingRequest(req );
                
                tempurl.searchParams.forEach(function (value, key, parent) {
                    self.appData.addQueryParam(key, value);
                });
                if (req.url().startsWith(self.appData.site_url.origin)){
                    console.log("[WC] Intercepted in processRequest ", req.url(), req.method());
                    let basename = path.basename(tempurl.pathname);
                    if (req.url().indexOf("rest") > -1 && (req.method() === "POST" || req.method() === "PUT")){
                        //console.log(basename, req.method(), req.headers(), req.resourceType());
                    }

                    let foundRequest = FoundRequest.requestObjectFactory(req, self.appData.site_url.href);
                    foundRequest.from="InterceptedRequest";

                    let allParams2 = foundRequest.getAllParams();
                    for (let pkey in allParams2){
                        let pvalue = allParams2[pkey];
                        if (typeof pvalue === "object"){
                            pvalue = pvalue.values().next().value;
                        }
                        self.appData.addQueryParam(pkey, pvalue);
                    }

                    if (self.appData.addInterestingRequest(foundRequest) > 0){
                        self.requestsAdded++;
                        //console.log("[WC] ${GREEN} ${GREEN} ADDED ${ENDCOLOR}${ENDCOLOR}intercepted request req.url() = ", req.url());
                    }
                    // skip if it has a period for nodejs apps

                    let result = self.appData.addRequest(foundRequest);
                    if (result){
                        console.log(`\x1b[38;5;2mINTERCEPTED REQUEST and ${GREEN} ${GREEN} ADDED ${ENDCOLOR}${ENDCOLOR} #${self.appData.collectedURL} ${req.url()} RF size = ${self.appData.numRequestsFound()}\x1b[0m`);
                    } else {
                        logLimited(`repeat-url:${req.url()}`, `INTERCEPTED and ABORTED repeat URL ${req.url()}`);
                    }
                } else {
                    
                    if (req.url().indexOf("gremlins") > -1){
                        //console.log("[WC] CONTINUING with getting some gremlins in here.");
                        req.continue();
                    } else {
                        try{
                            let url = new URL(req.url());
                            if (req.url().startsWith("image/") || url.pathname.endsWith(".gif") || url.pathname.endsWith(".jpeg") || url.pathname.endsWith(".jpg") || url.pathname.endsWith(".woff") || url.pathname.endsWith(".ttf")){
                            
                            } else {
                                //console.log(`[WC] Ignoring request for ${req.url().substr(0,200)}`)
                            }
                        } catch (e){
                            //console.log(`[WC] Ignoring request for malformed url = ${req.url().substr(0,200)}`)
                        }
                        if (self.isLoading){
                            req.continue();
                        } else {
                            req.respond(req.redirectChain().length
                              ? { body: '' } // prevent 301/302 redirect
                              : { status: 204 } // prevent navigation by js
                            );
                        }
                    }
                    return;
                }
                // What to do, from here
                //console.log("PROCESSED ", req.url(), req.isNavigationRequest());
                if (false && req.frame() === self.page.mainFrame()){
                    console.log(`[WC] Aborting request b/c frame == mainframe for ${req.url().substr(0,200)}`)
                    //req.abort('aborted');
                    req.respond(req.redirectChain().length
                      ? { body: '' } // prevent 301/302 redirect
                      : { status: 204 } // prevent navigation by js
                    )
                } else {
                    if (req.isNavigationRequest() && req.frame() === self.page.mainFrame() ) {
                        if (typeof self.last_nav_request !== "undefined" && self.last_nav_request === req.url()){
                            logLimited(`repeat-nav:${req.url()}`, "[WC] Aborting request b/c this is the same as last nav request, ignoring");
                            
                            self.last_nav_request = req.url();
                            req.respond(req.redirectChain().length
                              ? { body: '' } // prevent 301/302 redirect
                              : { status: 204 } // prevent navigation by js
                            )
                            return;
                        }
                        self.last_nav_request = req.url();
                        if (req.url().indexOf("gremlins") > -1){
                            //console.log("[WC] CONTINUING with getting some gremlins in here.");
                            req.continue();
                            return;
                        }
                        if (self.isLoading){
                            //console.log(`[WC] \tRequest granted while still in loading phase ${req.resourceType()} ${req.url()} `);
                            req.continue();
                        } else {
                                // if(req.respond(req.redirectChain().length)) {
                                //     console.log(`[WC] \tNavigation Request in mainFrame preventing 301/302 redirect ${req.url()}`);
                                // } else{
                                //     console.log(`[WC] \tNavigation Request in mainFrame denied ${req.url()} using 204`);
                                // }
                        
                                req.respond(req.redirectChain().length
                                  ? { body: '' } // prevent 301/302 redirect
                                  : { status: 204 } // prevent navigation by js
                                )
                            //req.abort();
                        }

                    } else {

                        // NON-mainFrame or not a navigation reque, shouldn't change page navigation

                        // var pdata = {
                        //     headers: {
                        //         ...req.headers(),
                        //         "Content-Type": "application/x-www-form-urlencoded"
                        //     }
                        // };
                        // if (!("Authorization" in pdata.headers)){
                        //     pdata.headers["Authorization"] = self.bearer;
                        // }
                        // let cookiestr = "";
                        // for (let cookie of self.cookies){
                        //     cookiestr += `${cookie.name}=${cookie.value}; `
                        // }
                        // pdata.headers["Cookie"] = cookiestr;
                        // console.log("\nprocessRequest REFORMED continue --- > nav req = ", req.isNavigationRequest(),
                        //     "is main frame = ", req.frame() === self.page.mainFrame(),
                        //     "is loading = ", self.isLoading,
                        //     "url = ", req.url(), "\n");
                        if (req.frame() === self.page.mainFrame()){
                            if (self.isLoading){

                                self.loadedURLs.push(tempurl.origin + tempurl.pathname);
                                req.continue();
                            } else {
                                req.continue();
                                // if (self.loadedURLs.includes(tempurl.origin + tempurl.pathname)){
                                //     console.log(`[WC] \tAllowing reload of frame ${req.url()}`);
                                //     req.continue();
                                // } else {
                                //     req.abort();
                                // }
                            }
                        } else {
                            req.continue()
                        }

                    }
                }

            }
        } // end processrequest

        console.log(`[\x1b[38;5;5mWC\x1b[0m] Browser launching with  url=${this.url.href} `);

        try {
            try{
                this.browser = await puppeteer.launch({
                    headless: this.appData.headless, 
                    args: [
                        "--disable-features=site-per-process", 
                        "--window-size=1600,900",
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu"
                    ], 
                    "defaultViewport": null 
                });
                console.log("OPENED BROWSER!");
                this.browser_up = true;
            } catch (xerror) {
                //console.log("UNABLE TO OPEN X DISPLAY");
                if (xerror.message.indexOf("Unable to open X display") > -1){
                    this.browser = await puppeteer.launch({
                        headless: this.appData.headless, 
                        args: [
                            "--disable-features=site-per-process",
                            "--no-sandbox",
                            "--disable-setuid-sandbox",
                            "--disable-dev-shm-usage",
                            "--disable-gpu"
                        ] 
                    });
                    this.browser_up = true;
                } else {
                    this.browser_up = false;
                    // noinspection ExceptionCaughtLocallyJS
                    throw(xerror);
                }
            }
            
            let gremlinsErrorTest = setInterval(function(){
                if (self.gremlins_error && self.lamehord_done){
                    console.log("Ohh no, they killed Gizmo!, and the lamhord completed.  Aborting!!!");
                    try{
                        triggerAbortCurrentRequest();
                        if (self.browser && typeof self.browser.close === "function"){
                            Promise.race([
                                self.browser.close(),
                                new Promise((resolve) => setTimeout(resolve, 3000)),
                            ]).catch(() => {});
                        }
                    } catch (err){
                        console.log("\tProblem closing browser after timeout\n");
                    }
                    self.gremlins_error = false;
                }
            }, 10*1000);

            this.page = await this.browser.newPage();

            try {
                await this.page.evaluate(() => console.log(`url is ${location.href}`));

                await this.page.setRequestInterception(true);

                if (this.loginData !== undefined && 'form_url' in this.loginData){
                    if (!this.hasCompleteLoginSelectors()){
                        console.log("[WC] Skip login: missing usernameSelector/passwordSelector in request_crawler config");
                    } else if (!this.hasValidLoginFormUrl()){
                        console.log("[WC] Skip login: missing/invalid form_url in request_crawler config");
                    } else {
                        let loginCookies = await this.do_login(this.page);
                        await this.addCookiesToPage(loginCookies, this.cookieData, this.page).catch(function (error) {
                            console.log("COOKIE ERROR:!!!", error)
                        });
                    }
                }
                let childFrames = await this.page.mainFrame().childFrames();
    
                if (typeof childFrames !== 'undefined' && childFrames.length > 0){
                    for (const frame of childFrames){
                        // await frame.setRequestInterception(true);
                        // frame.on('request', processRequest);
                        
                        console.log(`[WC] adding processRequest for ${frame.url()}`)
                    }
                }
                this.page.on('request', processRequest);

                this.page.on('console', consoleLog);
                this.page.on('pageerror', pageError);

                this.browser.on('targetchanged', targetChanged);

                await this.page.setCacheEnabled(false);
                await this.page.setDefaultNavigationTimeout(0);

                const exercisePromise = this.exerciseTarget(this.page).catch((ex) => {
                    console.log("[WC] exerciseTarget error, skip current request");
                    try{
                        console.log(ex && ex.stack ? ex.stack : ex);
                    } catch(inner){
                    }
                });
                const abortPromise = new Promise((resolve) => {
                    this.abortPromiseResolver = resolve;
                });
                await Promise.race([exercisePromise, abortPromise]);
                this.abortPromiseResolver = null;

                this.reportResults();

            } catch (e) {
                console.log(`Error: cannot start browser `);
                console.log(e.stack);
            } finally {
                if (this.pagetimeout){
                    console.log("[WC] \x1b[38;5;10mRemoving page timer for browser \x1b[0m");
                    clearTimeout(this.pagetimeout);
                }
                if (this.pagekilltimeout){
                    clearTimeout(this.pagekilltimeout);
                }
                this.abortPromiseResolver = null;
                clearInterval(gremlinsErrorTest);
                //console.log(`current request = ${this.appData.requestsFound[this.currentRequestKey]}`)
                try{
                    if (this.browser && typeof this.browser.close === "function"){
                        await Promise.race([
                            this.browser.close(),
                            new Promise((resolve) => setTimeout(resolve, 5000)),
                        ]);
                    }
                } catch(closeErr){
                    console.log("[WC] browser.close() failed in finally; continue to next request");
                }
            }

        } catch (browsererr) {
            console.log(`Error: with Starting browser or creating new page `);
            console.log(browsererr.stack);
        }

    }

}

//module.exports = {AppData:AppData, RequestExplorer:RequestExplorer};


/*
 *
 *
 *
 *
 *
 *
 */
