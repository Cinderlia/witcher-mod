# Witcher Crawler Optimization Summary

This document details the optimizations and heuristic improvements made to Witcher's request crawler (`input_sifter2.js` and `param_minimizer.js`) to enhance exploration depth, stability, and compatibility with downstream Fuzzing processes.

## 1. Smart Retention of HTTP Error Pages
**Problem:** The crawler and parameter minimizer previously discarded pages returning HTTP status codes `>= 400` (e.g., 500 Internal Server Error).
**Solution:**
- Added an `isInteractivePageQuiet` check (in `param_minimizer.js`) and `isInteractive` check (in `input_sifter2.js`).
- If an error page contains interactive HTML elements or *any* response body, it is now deemed highly valuable (as it indicates PHP code execution crashed or hit an edge case).
- **Behavior:** The crawler stops *clicking* through these error pages (to prevent getting stuck) but *saves* them into `request_data.json` so AFL++ can fuzz them.

## 2. Dual-Queue Time-Sliced Exploration (Native vs. Seeded URLs)
**Problem:** Static analysis URLs (from `code_scan`) were added but not prioritized, leading to missed heuristic paths.
**Solution:**
- The crawler now maintains two separate queues: `requestsFound` (natively discovered via clicking) and `seedRequestsFound` (externally injected from `afl_request_data.json`).
- Implemented a round-robin time-sliced scheduler (`_timeSliceIndex`).
- The crawler now spends a quota of rounds exploring natively discovered links and then switches to exploring injected seed links, ensuring external seeds are actively clicked and explored by Gremlins.

## 3. OOM Protection: Long Form Payload Truncation
**Problem:** Large configuration pages (e.g., Joomla's `com_config` with hundreds of input fields) caused Node.js `v8` heap out-of-memory (OOM) crashes.
**Solution:**
- **Payload Truncation:** In `searchForInputs`, if the base form data string exceeds 5000 characters, it is cleanly truncated at the last complete parameter (`&`) before generating the POST request.
- **Combinatorial Explosion Limit:** When generating POST requests from multi-select dropdowns (`multipleParamKeys`), the crawler no longer computes the full Cartesian product. It now limits combinations to a hard maximum of 50 permutations (`maxPermutations = 50`) and restricts each key to a maximum of 5 values.

## 4. Anti-Stagnation Heuristic (Value-Explosion Protection)
**Problem:** Monkey testing (Gremlins.js) would often repeatedly click the same form (e.g., submitting a search form with randomly generated dates/strings). Because the values were different, the structural deduplication failed to drop them, causing the crawler to get stuck exploring the same page infinitely.
**Solution:**
- Introduced a `seenKeysForThisPage` Set to track the unique parameter *keys* discovered during a page's exploration loop.
- **Smart Heuristic:** If Gremlins generates new requests for 3 consecutive time slices but *fails to introduce any new parameter keys* (i.e., only the values are changing), the crawler detects "Key Stagnation".
- **Action:** It triggers a `CRITICAL` abort, forcefully breaking the exploration loop for that specific URL and moving on to the next target, perfectly protecting memory without relying on an arbitrary hard limit.

## 5. Downstream AFL Seed Extraction Fixes (`witcher.py`)
**Problem:** The downstream pipeline that feeds `request_data` to AFL++ was severely flawed.
**Solution:**
- **Removed Hard Truncation:** Removed the hardcoded `requests = requests[:10]` logic that discarded 80% of valid seeds.
- **Parameter Diversity Greedy Selection:** Replaced the hard limit with a smart Greedy Algorithm. If a target has > 50 seeds, the script parses all parameters and selects the 50 seeds that provide the maximum diversity of unique parameter keys.
- **Full Header Retention:** Removed the logic that discarded custom HTTP headers. Now, all business-critical headers (e.g., `Authorization`, custom tokens) discovered by the crawler are fully preserved and compiled into the AFL seed format.
