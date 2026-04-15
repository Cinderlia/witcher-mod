#! /usr/bin/env node

import fs from 'fs';
import path from 'path';
import http from 'http';
import process from  'process';

const COOKIE_INDEX = 0;
const GET_INDEX = 1;
const POST_DATA_INDEX = 2;

import {AppData, RequestExplorer} from "./input_sifter2.js";
import {FoundRequest} from "./FoundRequest.js";

var BASE_SITE = "";
var BASE_APPDIR = "";
var RUNCNT = "";

function wcStartupLog(baseAppdir, msg){
    try{
        let fn = path.join(baseAppdir, "crawler_startup.log");
        let line = `[${(new Date()).toISOString()}] ${msg}\n`;
        fs.appendFileSync(fn, line, {encoding:"utf8"});
    } catch(ex){
    }
}

function wcInitRuntimeLogger(baseAppdir){
    try{
        let fn = path.join(baseAppdir, "crawler_runtime.log");
        let stream = fs.createWriteStream(fn, {flags:"a"});
        let origLog = console.log;
        let origErr = console.error;
        let safeRepr = (v) => {
            try{
                if (v === null){
                    return "null";
                }
                if (typeof v === "string"){
                    return v;
                }
                if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint"){
                    return String(v);
                }
                if (v instanceof Error){
                    return (v && v.stack) ? v.stack : String(v);
                }
                if (typeof v === "undefined"){
                    return "undefined";
                }
                if (typeof v === "function"){
                    return "[Function]";
                }
                if (typeof v === "object"){
                    let name = "";
                    try{
                        name = v && v.constructor && v.constructor.name ? v.constructor.name : "";
                    } catch(ex){
                        name = "";
                    }
                    // For simple objects, stringify them to capture data (like {msg: "error"} )
                    if (name === "Object" || name === "") {
                        try {
                            return JSON.stringify(v);
                        } catch (e) {
                            return "[Unserializable Object]";
                        }
                    }
                    return name ? `[${name}]` : "[Object]";
                }
                return String(v);
            } catch(ex){
                return "[Unserializable]";
            }
        };
        let writeLine = (line) => {
            try{
                stream.write(`[${(new Date()).toISOString()}] ${line}\n`);
            } catch(ex){
            }
        };
        console.log = (...args) => {
            try{
                writeLine(args.map(safeRepr).join(" "));
            } catch(ex){
            }
            origLog(...args);
        };
        console.error = (...args) => {
            try{
                writeLine(args.map(safeRepr).join(" "));
            } catch(ex){
            }
            origErr(...args);
        };
        process.on("uncaughtException", (err) => {
            try{
                writeLine(`uncaughtException ${(err && err.stack) ? err.stack : String(err)}`);
            } catch(ex){
            }
        });
        process.on("unhandledRejection", (reason) => {
            try{
                writeLine(`unhandledRejection ${(reason && reason.stack) ? reason.stack : String(reason)}`);
            } catch(ex){
            }
        });
        writeLine("logger_ready");
    } catch(ex){
    }
}

// buildRequest consumes url and returns
// it does this by spliting the path on / and reversing the results.  Starting with the last value it
// finds the longest path that exists based on the provided path.
function get_fuzzer_output_dirname(apath, runcnt){

    //apath = apath.replace("/","+");
    var build_dn = "";
    var final_fop = "";
    apath.split("/").reverse().forEach(function (ele) {
        if (build_dn === ""){
            build_dn = ele;
        } else {
            build_dn = ele + "+" + build_dn;
        }

        let fuzzer_output_path = path.join(BASE_APPDIR,"fin_outs",runcnt + build_dn, "fuzzer-master","queue");
        if (fs.existsSync(fuzzer_output_path)){
            final_fop = fuzzer_output_path;
        }
    });

    return final_fop;

}

function convertFilePathToURL(apath){

    var build_url = "";
    let urls = [];
    apath.split("/").reverse().forEach(function (ele) {
        if (build_url === ""){
            build_url = ele;
        } else {
            build_url = ele + "/" + build_url;
        }

        let url = new URL(BASE_SITE + "/" + build_url);
        let options = {method: 'HEAD', host: url.hostname, port: url.port, path: url.pathname, headers:{Connection:"close"}};

        req = http.request(options, function(r) {
            //console.log(url.href, build_url, r.statusCode);
            if (r.statusCode === 200) {
                urls.push(url);
            } else if (r.statusCode === 302){
                // if ("location" in r.headers && isDefined(r.headers['location'])){
                //     url = new URL(r.headers['location']);
                //     onURLExists(fop, url);
                // }
                //onURLExists(fop, url);
            } else {
                // do nothing, keep trying
            }

        });
        req.end();
    });
    return urls;
}


function addInputsToRequestsFound(requestInputDir, url, appData){
    let fop_master_queue = requestInputDir;
    var paths_to_test = fs.readdirSync(fop_master_queue,'utf8');
    var finished = false;
    //paths_to_test.forEach((input_fn, index) =>{

    for (const inputFilename of paths_to_test) {

        if (finished){
            break;
        }
        var input_filepath = path.join(fop_master_queue,inputFilename);

        if (fs.lstatSync(input_filepath).isFile()){

            //finished = true;
            const input_data = fs.readFileSync(input_filepath, 'binary');
            let requestData = {base_url:url, [COOKIE_INDEX]:"", [GET_INDEX]:"", [POST_DATA_INDEX]:""};
            input_data.split("\x00").forEach(function(requestElement, index){
                // reads cookie, get, and post data from file and updates dictionary
                requestData[index] = requestElement
            });
            // const clen = requestData[COOKIE_INDEX].length;
            // const glen = requestData[GET_INDEX].length;
            const plen = requestData[POST_DATA_INDEX].length;
            var necessaryParams = "";
            let inputSearchParams = requestData[GET_INDEX];
            if (inputSearchParams.startsWith("?")){
                inputSearchParams = inputSearchParams.substring(1);
            }
            url.searchParams.forEach(function (value, key, parent){
                let param=`${key}=`;
                if (inputSearchParams.indexOf(param) === -1 && param.length>1){
                    necessaryParams += param + value + "&";
                }
            });
            let urlstr = "";
            if (necessaryParams.length > 0){
                urlstr = `${url.origin}${url.pathname}?${necessaryParams}${inputSearchParams}`;
            } else {
                urlstr = `${url.origin}${url.pathname}?${inputSearchParams}`;
            }

            console.log("STING URL HERE",urlstr);
            if (plen > 0 ){
                appData.addRequest(FoundRequest.requestParamFactory(urlstr, "POST", requestData[POST_DATA_INDEX], {}, "initialLoad", requestData[COOKIE_INDEX]));
            }
            appData.addRequest(FoundRequest.requestParamFactory(urlstr, "GET", requestData[GET_INDEX], {}, "initialLoad", requestData[COOKIE_INDEX]));

        }

    }
    //console.log(requestsFound);
}



async function explorationWorker(workernum, appData){
    await sleep(50);

    if (appData.numRequestsFound() === 0){
        let re = new RequestExplorer(appData, workernum, BASE_APPDIR);

        await re.start();
    }
    let nextRequest = appData.getNextRequest();
    while (nextRequest != null){
        try{
            let stopFn = path.join(BASE_APPDIR, "STOP_CRAWLER");
            if (fs.existsSync(stopFn)){
                console.log("[WC] STOP_CRAWLER file detected, exiting");
                process.exit(97);
            }
        } catch(ex){
        }

        let re = new RequestExplorer(appData, workernum, BASE_APPDIR, nextRequest);
        await re.start();

        console.log("\x1b[38;5;12m^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Completed " + appData.currentRequest.url() + " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ \x1b[0m\n");
        appData.updateReqsFromExternal()
        nextRequest = appData.getNextRequest();
    }

}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function startExploration(workers=1, appData){

    // if (appData.hasRequests()){
    //     console.log("ERROR, no requests in queue!");
    //     throw error("Failed to find any requests to process");
    // }
    for (let i=0; i < workers;i++){
        //sleep(i*10000);
        explorationWorker(i, appData);
    //    setTimeout(explorationWorker, 3000*i, i, appData);

        console.log("Started worker ", i)
    }
    let currentURLRound = appData.currentURLRound;

    console.log(`DoNeDoNeDoNeDoNeDoNeDoNeDoNe ${currentURLRound} DoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNe`);
    console.log(`DoNeDoNeDoNeDoNeDoNeDoNeDoNe ${currentURLRound} DoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNe`);
    console.log(`DoNeDoNeDoNeDoNeDoNeDoNeDoNe ${currentURLRound} DoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNe`);
    console.log(appData.getRequestInfo());
    console.log(`DoNeDoNeDoNeDoNeDoNeDoNeDoNe ${currentURLRound} DoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNe`);
    console.log(`DoNeDoNeDoNeDoNeDoNeDoNeDoNe ${currentURLRound} DoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNe`);
    console.log(`DoNeDoNeDoNeDoNeDoNeDoNeDoNe ${currentURLRound} DoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNeDoNe`);
}

if (process.argv.length > 3) {
    console.log(process.argv)

    let args = process.argv.slice(2);
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
    if (args.length < 2){
        console.log("ERROR, an input file was not provided");
        console.log("Usage:\n\tnode main.js \x1b[38;5;5mBASE_SITE BASE_APPDIR \x1b[38;5;4m[RUNCNT]\x1b[0m\n\n");
        process.exit(2);
    }

    BASE_SITE = args[0];
    BASE_APPDIR = args[1];
    RUNCNT = args.length > 2 ? args[2] : "";
    wcInitRuntimeLogger(BASE_APPDIR);
    try{
        console.log(`[WC][START] base_site=${BASE_SITE} base_appdir=${BASE_APPDIR} cwd=${process.cwd()}`);
        wcStartupLog(BASE_APPDIR, `[WC][START] base_site=${BASE_SITE} base_appdir=${BASE_APPDIR} cwd=${process.cwd()}`);
        let rd = path.join(BASE_APPDIR, "request_data.json");
        let afl = path.join(BASE_APPDIR, "afl_request_data.json");
        console.log(`[WC][START] request_data_exists=${fs.existsSync(rd)} afl_request_data_exists=${fs.existsSync(afl)}`);
        wcStartupLog(BASE_APPDIR, `[WC][START] request_data_exists=${fs.existsSync(rd)} afl_request_data_exists=${fs.existsSync(afl)}`);
    } catch(ex){
    }
    var files_fn = path.join(BASE_APPDIR, "files.dat");
    var SEED_DIR = path.join(BASE_APPDIR, "input");

    //session_id = get_a_session();
    let appData = new AppData(true, BASE_APPDIR, BASE_SITE, headless);


    if (fs.existsSync(files_fn)){
        let paths_to_test = fs.readFileSync(files_fn,'utf8');

        paths_to_test.split('\n').forEach(function(apath){

            let fuzzer_out_path = SEED_DIR;
            let urls = convertFilePathToURL(apath);
            for (let url of urls){
                if (RUNCNT !== "") {
                    appData.usingFuzzingDir();
                    fuzzer_out_path = get_fuzzer_output_dirname(apath, RUNCNT);
                    if (fs.existsSync(fuzzer_out_path)){
                        addInputsToRequestsFound(fuzzer_out_path, url, appData);
                    }
                } else {
                    //appData.addRequest(url.href,"GET","","initial","");
                }
            }

        });

    }
    // wait a few seconds for a few url requests to complete first
    setTimeout(startExploration,2000, 1, appData);

} else {
    console.log(process.argv)
    console.log("ERROR, an input file was not provided");
    console.log("Usage:\n\tnode main.js \x1b[38;5;5mBASE_SITE BASE_APPDIR \x1b[38;5;4m[RUNCNT]\x1b[0m\n\n");

}
