#!/usr/bin/env node
/**
 * ============================================================================
 * LC79 SUPER HYBRID AI ANALYZER API SERVER v4.1 VIP EDITION (TX & MD5)
 * ============================================================================
 * - Nguồn API TX & MD5 & Thuật toán gốc SuperHybridAIEngine v3.0: GIỮ NGUYÊN 100%
 * - Fix lỗi crash Render (xóa khai báo trùng const https)
 * - Giao diện API Phiên chuẩn mẫu JSON raw + nút "Tạo bản in đẹp"
 * - Quản lý Khóa / Mở từng API (MD5, TX, API Gốc, API Tổng hợp)
 * - Đăng nhập Admin bảo vệ trang quản trị (vkhanh / 2011), API mở công khai trừ khi bị khóa
 * - Bổ sung API Gốc chưa phân tích (/api/raw/md5, /api/raw/tx, /api/raw/all)
 * - Mã hóa mã nguồn web & mã hóa Nhật ký mạng (Network Payload Encryption) chống crack
 * ============================================================================
 */

"use strict";

const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { spawnSync } = require("node:child_process");

const PORT = Number(process.env.PORT) || 3000;
const POLL_INTERVAL_MS = 2000;

// ============================================================================
// NGUỒN API TX & MD5 LẤY TỪ SCRIPT TOOL ROBOT.JS
// ============================================================================
const TX_API_URL = "https://wtx.tele68.com/v1/tx/sessions";
const TX_TOOL_ENDPOINTS = [
    TX_API_URL,
    "https://api.allorigins.win/raw?url=" + encodeURIComponent(TX_API_URL),
    "https://corsproxy.io/?" + encodeURIComponent(TX_API_URL),
    "https://api.codetabs.com/v1/proxy?quest=" + encodeURIComponent(TX_API_URL),
];

const MD5_API_URL = "https://wtxmd52.tele68.com/v1/txmd5";
const MD5_API_LITE_URL =
    "https://wtxmd52.tele68.com/v1/txmd5/lite-sessions?cp=R&cl=R&pf=web&at=405f18b5220fdd5674e8bb74bd0d5d14";
const MD5_TOOL_ENDPOINTS = [
    MD5_API_LITE_URL,
    `${MD5_API_URL}/sessions?cp=R&cl=R&pf=web&at=405f18b5220fdd5674e8bb74bd0d5d14`,
    `${MD5_API_URL}/sessions?cp=R&cl=R&pf=web&at=`,
    `${MD5_API_URL}/sessions`,
    "https://api.allorigins.win/raw?url=" + encodeURIComponent(`${MD5_API_URL}/sessions`),
    "https://corsproxy.io/?" + encodeURIComponent(`${MD5_API_URL}/sessions`),
    "https://api.codetabs.com/v1/proxy?quest=" + encodeURIComponent(`${MD5_API_URL}/sessions`),
];

function httpRequestJson(targetUrl, options = {}) {
    if (typeof globalThis.fetch === "function") {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), options.timeout || 10000);
        return globalThis.fetch(targetUrl, {
            ...options,
            signal: controller.signal,
            cache: "no-store",
        })
            .then(async res => {
                clearTimeout(timer);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const text = await res.text();
                let parsed = JSON.parse(text);
                if (typeof parsed === "string") parsed = JSON.parse(parsed);
                return parsed;
            })
            .catch(err => {
                clearTimeout(timer);
                throw err;
            });
    }
    return new Promise((resolve, reject) => {
        const parsed = new URL(targetUrl);
        const client = parsed.protocol === "https:" ? https : http;
        const req = client.request(
            {
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
                path: parsed.pathname + parsed.search,
                method: options.method || "GET",
                headers: options.headers || {},
                timeout: options.timeout || 10000,
            },
            res => {
                let raw = "";
                res.setEncoding("utf8");
                res.on("data", chunk => { raw += chunk; });
                res.on("end", () => {
                    if (res.statusCode < 200 || res.statusCode >= 300) {
                        return reject(new Error(`HTTP ${res.statusCode}`));
                    }
                    try {
                        let json = JSON.parse(raw);
                        if (typeof json === "string") json = JSON.parse(json);
                        resolve(json);
                    } catch (err) {
                        reject(err);
                    }
                });
            }
        );
        req.on("error", reject);
        req.on("timeout", () => { req.destroy(new Error("Request timeout")); });
        if (options.body) req.write(options.body);
        req.end();
    });
}

// ============================================================================
// THUẬT TOÁN PHÂN TÍCH GIỮ NGUYÊN 100% TỪ v1-v3.js (KHÔNG CHỈNH SỬA DÒNG NÀO)
// ============================================================================
const MAX_STORE_ROUNDS = 200;
const WINDOW_20_ROUNDS = 20;

const DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "Cache-Control": "no-cache",
    "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
};

// ============================================================================
// PHẦN 1: CÁC HÀM GỐC TỪ apilc79auto.js (GIỮ NGUYÊN 100% ÉP BUỘC)
// ============================================================================
function extractFeatures(history) {
    const tx = history.map(h => h.tx === "T" ? "t" : "x");
    const totals = history.map(h => h.total);
    const freq = {};
    for (const v of tx) freq[v] = (freq[v] || 0) + 1;
    let runs = [], cur = tx[0], len = 1;
    for (let i = 1; i < tx.length; i++) {
        if (tx[i] === cur) len++;
        else { runs.push({ val: cur, len }); cur = tx[i]; len = 1; }
    }
    if (tx.length) runs.push({ val: cur, len });
    return { tx, totals, freq, runs, maxRun: runs.reduce((m, r) => Math.max(m, r.len), 0) };
}

function detectPatternType(runs) {
    if (runs.length < 3) return null;
    const lastRuns = runs.slice(-6);
    const lengths = lastRuns.map(r => r.len);
    const values = lastRuns.map(r => r.val);
    if (lastRuns.length >= 3) {
        if (lengths.every(l => l === 1) && values.every((v, i) => i === 0 || v !== values[i - 1])) return "1_1_pattern";
        if (lengths.every(l => l === 2) && values.every((v, i) => i === 0 || v !== values[i - 1])) return "2_2_pattern";
        if (lengths.every(l => l === 3) && values.every((v, i) => i === 0 || v !== values[i - 1])) return "3_3_pattern";
        if (lengths.length >= 5 && lengths[0] === 2 && lengths[1] === 1 && lengths[2] === 2 && lengths[3] === 1 && lengths[4] === 2) return "2_1_2_pattern";
        if (lengths.length >= 5 && lengths[0] === 1 && lengths[1] === 2 && lengths[2] === 1 && lengths[3] === 2 && lengths[4] === 1) return "1_2_1_pattern";
        if (lengths.length >= 5 && lengths[0] === 3 && lengths[1] === 2 && lengths[2] === 3 && lengths[3] === 2 && lengths[4] === 3) return "3_2_3_pattern";
        if (lengths.length >= 5 && lengths[0] === 4 && lengths[1] === 2 && lengths[2] === 4 && lengths[3] === 2 && lengths[4] === 4) return "4_2_4_pattern";
        if (lengths.length >= 5 && lengths[0] === 2 && lengths[1] === 2 && lengths[2] === 1 && lengths[3] === 2 && lengths[4] === 2) return "2_2_1_pattern";
        if (lengths.length >= 5 && lengths[0] === 1 && lengths[1] === 3 && lengths[2] === 1 && lengths[3] === 3 && lengths[4] === 1) return "1_3_1_pattern";
        if (lengths.length >= 5 && lengths[0] === 3 && lengths[1] === 1 && lengths[2] === 3 && lengths[3] === 1 && lengths[4] === 3) return "3_1_3_pattern";
    }
    const lastRun = lastRuns[lastRuns.length - 1];
    if (lastRun && lastRun.len >= 5) return "long_run_pattern";
    return null;
}

function predictFromPattern(patternType, runs, lastTx) {
    if (!patternType) return null;
    const lastRun = runs[runs.length - 1];
    switch (patternType) {
        case "1_1_pattern": return lastTx === "t" ? "x" : "t";
        case "2_2_pattern": return lastRun.len === 2 ? (lastRun.val === "t" ? "x" : "t") : lastRun.val;
        case "3_3_pattern": return lastRun.len === 3 ? (lastRun.val === "t" ? "x" : "t") : lastRun.val;
        case "2_1_2_pattern":
            if (lastRun.len === 2) return lastRun.val === "t" ? "x" : "t";
            if (lastRun.len === 1) return lastRun.val;
            return null;
        case "1_2_1_pattern":
            if (lastRun.len === 1) return lastRun.val === "t" ? "x" : "t";
            if (lastRun.len === 2) return lastRun.val;
            return null;
        case "3_2_3_pattern":
        case "4_2_4_pattern":
            if (lastRun.len >= 3) return lastRun.val === "t" ? "x" : "t";
            if (lastRun.len === 2) return lastRun.val;
            return null;
        case "2_2_1_pattern":
            if (lastRun.len === 2) return lastRun.val === "t" ? "x" : "t";
            if (lastRun.len === 1) return lastRun.val === "t" ? "x" : "t";
            return null;
        case "1_3_1_pattern":
            if (lastRun.len === 1) return lastRun.val === "t" ? "x" : "t";
            if (lastRun.len === 3) return lastRun.val;
            return null;
        case "3_1_3_pattern":
            if (lastRun.len === 3) return lastRun.val === "t" ? "x" : "t";
            if (lastRun.len === 1) return lastRun.val;
            return null;
        case "long_run_pattern":
            if (lastRun.len > 7) return lastRun.val === "t" ? "x" : "t";
            if (lastRun.len >= 4) return lastRun.val;
            return null;
        default: return null;
    }
}

function parseLines(data) {
    if (!data || !Array.isArray(data.list)) return [];
    const sortedList = [...data.list].sort((a, b) => (b.id || 0) - (a.id || 0));
    const arr = sortedList
        .map(item => {
            const dices = Array.isArray(item.dices)
                ? item.dices.map(Number)
                : Array.isArray(item.dice)
                    ? item.dice.map(Number)
                    : [];
            const point = dices.length === 3
                ? dices.reduce((s, v) => s + v, 0)
                : Number(item.point ?? item.sum ?? item.total ?? 0);
            if (!item.id || point < 3 || point > 18) return null;
            return {
                session: Number(item.id),
                dice: dices,
                total: point,
                result: item.resultTruyenThong || item.result || (point >= 11 ? "TAI" : "XIU"),
                tx: point >= 11 ? "T" : "X",
            };
        })
        .filter(Boolean);
    return arr.sort((a, b) => a.session - b.session);
}

function formatMoney(n) {
    const num = Math.round(Number(n) || 0);
    const sign = num < 0 ? "-" : "";
    return sign + Math.abs(num).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

function parseMoneyInput(raw, fallback = 0) {
    if (raw === null || raw === undefined) return fallback;
    let s = String(raw).trim().toLowerCase().replace(/\s+/g, "").replace(/đ|xu|vnd/g, "");
    if (!s) return fallback;
    let mult = 1;
    if (s.endsWith("m") || s.endsWith("tr")) {
        mult = 1000000;
        s = s.replace(/(m|tr)$/, "");
    } else if (s.endsWith("k")) {
        mult = 1000;
        s = s.replace(/k$/, "");
    }
    s = s.replace(/\./g, "").replace(/,/g, ".");
    const val = parseFloat(s);
    if (Number.isNaN(val)) return fallback;
    return Math.round(val * mult);
}

const PATTERN_DB = {
    "tttt":    { t: 73, x: 27 }, "xxxx":    { t: 27, x: 73 },
    "tttttt":  { t: 83, x: 17 }, "xxxxxx":  { t: 17, x: 83 },
    "ttttx":   { t: 40, x: 60 }, "xxxxt":   { t: 60, x: 40 },
    "ttttttx": { t: 30, x: 70 }, "xxxxxxt": { t: 70, x: 30 },
    "ttxx":    { t: 62, x: 38 }, "xxtt":    { t: 38, x: 62 },
    "txx":     { t: 60, x: 40 }, "xtt":     { t: 40, x: 60 },
    "ttx":     { t: 65, x: 35 }, "xxt":     { t: 35, x: 65 },
    "txt":     { t: 58, x: 42 }, "xtx":     { t: 42, x: 58 },
    "tttx":    { t: 70, x: 30 }, "xxxt":    { t: 30, x: 70 },
    "ttxt":    { t: 63, x: 37 }, "xxtx":    { t: 37, x: 63 },
    "txxx":    { t: 25, x: 75 }, "xttt":    { t: 75, x: 25 },
    "ttxtx":   { t: 62, x: 38 }, "xxtxt":   { t: 38, x: 62 },
    "ttxxt":   { t: 55, x: 45 }, "xxttx":   { t: 45, x: 55 },
    "txtx":    { t: 52, x: 48 }, "xtxt":    { t: 48, x: 52 },
    "txtxt":   { t: 53, x: 47 }, "xtxtx":   { t: 47, x: 53 },
    "txtxtxt": { t: 57, x: 43 }, "xtxtxtx": { t: 43, x: 57 },
};

function detectStreak(vals) {
    if (!vals.length) return { streak: 0, current: null, breakProb: 0 };
    let streak = 1;
    const current = vals[vals.length - 1];
    for (let i = vals.length - 2; i >= 0; i--) {
        if (vals[i] === current) streak++;
        else break;
    }
    const last15 = vals.slice(-15);
    let switches = 0;
    for (let i = 1; i < last15.length; i++) {
        if (last15[i] !== last15[i - 1]) switches++;
    }
    const tCount = last15.filter(v => v === "t").length;
    const imbalance = Math.abs(tCount - (last15.length - tCount)) / last15.length;
    let breakProb = 0;
    if (streak >= 8) breakProb = Math.min(0.6 + (switches / 15) + imbalance * 0.15, 0.9);
    else if (streak >= 5) breakProb = Math.min(0.35 + (switches / 10) + imbalance * 0.25, 0.85);
    else if (streak >= 3 && switches >= 7) breakProb = 0.3;
    return { streak, current, breakProb };
}

function ngramPredict(vals) {
    const results = [];
    for (let len = 2; len <= 5; len++) {
        if (vals.length < len + 1) continue;
        const pattern = vals.slice(-len).join("");
        let tCount = 0, xCount = 0, total = 0;
        for (let i = 0; i <= vals.length - len - 1; i++) {
            const seg = vals.slice(i, i + len).join("");
            if (seg === pattern) {
                total++;
                if (vals[i + len] === "t") tCount++;
                else xCount++;
            }
        }
        if (total >= 2) {
            const prob = tCount / total;
            results.push({
                len,
                prediction: prob > 0.5 ? "t" : "x",
                confidence: Math.abs(prob - 0.5) * 200,
                samples: total,
                ratio: tCount + "/" + xCount,
            });
        }
    }
    results.sort((a, b) => (b.len * b.samples) - (a.len * a.samples));
    return results[0] || null;
}

function weightedTrend(vals) {
    const last15 = vals.slice(-15);
    if (last15.length < 3) return null;
    const weights = last15.map((_, i) => Math.pow(1.15, i));
    let tW = 0, xW = 0, totalW = 0;
    last15.forEach((v, i) => {
        totalW += weights[i];
        if (v === "t") tW += weights[i];
        else xW += weights[i];
    });
    const ratio = (tW - xW) / totalW;
    return {
        prediction: ratio > 0 ? "t" : "x",
        confidence: Math.abs(ratio) * 100,
    };
}

function meanDeviation(vals) {
    const last12 = vals.slice(-12);
    if (last12.length < 3) return null;
    const tCount = last12.filter(v => v === "t").length;
    const deviation = Math.abs(tCount - (last12.length - tCount)) / last12.length;
    if (deviation < 0.35) {
        return { prediction: last12[last12.length - 1] === "x" ? "t" : "x", confidence: 55 + deviation * 30 };
    }
    return { prediction: tCount > last12.length - tCount ? "t" : "x", confidence: 50 + deviation * 50 };
}

function detectCycle(vals) {
    if (vals.length < 20) return null;
    const values = vals.map(v => v === "t" ? 1 : -1);
    const n = values.length;
    let bestPeriod = 0, bestCorrelation = -1;
    for (let period = 2; period <= Math.floor(n / 3); period++) {
        let correlation = 0, count = 0;
        for (let i = 0; i < n - period; i++) {
            correlation += values[i] * values[i + period];
            count++;
        }
        correlation /= count;
        if (correlation > bestCorrelation) {
            bestCorrelation = correlation;
            bestPeriod = period;
        }
    }
    if (bestCorrelation < 0.2) return null;
    const position = vals.length % bestPeriod;
    const cycleResults = [];
    for (let j = position; j < vals.length; j += bestPeriod) {
        cycleResults.push(vals[j]);
    }
    const tCount2 = cycleResults.filter(r => r === "t").length;
    return {
        period: bestPeriod,
        correlation: bestCorrelation,
        prediction: tCount2 > cycleResults.length / 2 ? "t" : "x",
        confidence: Math.abs(tCount2 / cycleResults.length - 0.5) * 200,
    };
}

function markovPredict(vals) {
    const orders = [3, 2, 1];
    for (let oi = 0; oi < orders.length; oi++) {
        const order = orders[oi];
        if (vals.length <= order) continue;
        const table = {};
        for (let i = 0; i <= vals.length - order - 1; i++) {
            const key = vals.slice(i, i + order).join("\u2192");
            const next = vals[i + order];
            if (!table[key]) table[key] = { t: 0, x: 0 };
            table[key][next]++;
        }
        const state = vals.slice(-order).join("\u2192");
        const cnt = table[state];
        if (!cnt) continue;
        const total = cnt.t + cnt.x;
        if (total < 3) continue;
        return {
            prediction: cnt.t >= cnt.x ? "t" : "x",
            confidence: Math.round((Math.max(cnt.t, cnt.x) / total) * 100),
            order,
            samples: total,
        };
    }
    return null;
}

function fibonacciMomentum(vals) {
    if (vals.length < 10) return null;
    const fib = [1, 1, 2, 3, 5, 8, 13, 21];
    let tScore = 0, xScore = 0;
    for (let i = 0; i < Math.min(fib.length, vals.length); i++) {
        const idx = vals.length - 1 - i;
        if (vals[idx] === "t") tScore += fib[i];
        else xScore += fib[i];
    }
    const total = tScore + xScore;
    return {
        prediction: tScore > xScore ? "t" : "x",
        confidence: (Math.abs(tScore - xScore) / total) * 100,
    };
}

function smartBridgeBreak(vals) {
    if (vals.length < 3) return null;
    const si = detectStreak(vals);
    const streak = si.streak, current = si.current, breakProb = si.breakProb;
    if (streak < 3) return null;
    let breakProbability = breakProb;
    if (streak >= 6) breakProbability = Math.min(breakProbability + 0.15, 0.9);
    else if (streak >= 4) breakProbability = Math.min(breakProbability + 0.1, 0.85);
    else breakProbability = Math.max(breakProbability - 0.15, 0.15);
    const prediction = breakProbability > 0.65
        ? (current === "t" ? "x" : "t")
        : (current === "t" ? "t" : "x");
    return { prediction, confidence: breakProbability * 100, streak, breakProb: breakProbability };
}

function patternDBLookup(vals) {
    if (vals.length < 3) return null;
    const keys = Object.keys(PATTERN_DB).sort((a, b) => b.length - a.length);
    const currentStr = vals.slice(-15).join("");
    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (currentStr.endsWith(key)) {
            const data = PATTERN_DB[key];
            return { prediction: data.t > data.x ? "t" : "x", confidence: Math.max(data.t, data.x), pattern: key };
        }
    }
    return null;
}

function detectSpecialPatterns(vals) {
    if (vals.length < 4) return null;
    const last4 = vals.slice(-4);
    if (last4[0] === last4[1] && last4[2] === last4[3] && last4[1] !== last4[2]) {
        return { prediction: last4[3] === "t" ? "t" : "x", confidence: 62, pattern: "AABB" };
    }
    if (vals.length >= 6) {
        let alternating = true;
        for (let i = vals.length - 6; i < vals.length; i++) {
            if (i > vals.length - 6 && vals[i] === vals[i - 1]) { alternating = false; break; }
        }
        if (alternating) return { prediction: vals[vals.length - 1] === "t" ? "x" : "t", confidence: 65, pattern: "1-1" };
    }
    if (vals.length >= 5) {
        const m = vals.slice(-5);
        if (m[0] === m[1] && m[1] !== m[2] && m[3] === m[4] && m[0] === m[3]) {
            return { prediction: m[2], confidence: 62, pattern: "2-1" };
        }
    }
    return null;
}

function predictTaiXiuClassic(history, options = {}) {
    const vals = history.map(v => {
        if (typeof v === "string") {
            const lower = v.toLowerCase();
            if (lower === "t" || lower === "tài" || lower === "tai" || lower === "b" || lower === "banker") return "t";
            if (lower === "x" || lower === "xỉu" || lower === "xiu" || lower === "p" || lower === "player") return "x";
        }
        return v === 1 ? "t" : "x";
    });
    const n = vals.length;
    if (n < 3) return { val: "t", conf: 55, algos: ["Thu thập dữ liệu"], prob_t: 0.52, prob_x: 0.48, streak: 0, pattern: "" };
    let sT = 0, sX = 0;
    const algos = [];
    const last = vals[n - 1];
    const opp = last === "t" ? "x" : "t";
    const streakInfo = detectStreak(vals);
    const streak = streakInfo.streak;

    if (streak >= 6) {
        if (opp === "t") sT += 5.0; else sX += 5.0;
        algos.push(`Bệt Cực Mạnh (${streak})`);
    } else if (streak >= 4) {
        if (opp === "t") sT += 4.0; else sX += 4.0;
        algos.push(`Bệt Mạnh (${streak})`);
    } else if (streak >= 3) {
        if (opp === "t") sT += 3.0; else sX += 3.0;
        algos.push(`Bẻ Cầu (${streak})`);
    } else if (streak === 2) {
        if (last === "t") sT += 2.0; else sX += 2.0;
        algos.push("Theo Cầu (2)");
    } else {
        if (opp === "t") sT += 1.5; else sX += 1.5;
        algos.push("Xen Kẽ");
    }

    const ng = ngramPredict(vals);
    if (ng) {
        const w = ng.len * 0.8 + Math.min(ng.samples, 10) * 0.2;
        if (ng.prediction === "t") sT += w; else sX += w;
        algos.push(`N-Gram(${ng.len}:${ng.ratio})`);
    }

    const wt = weightedTrend(vals);
    if (wt) {
        if (wt.prediction === "t") sT += wt.confidence / 30; else sX += wt.confidence / 30;
        algos.push(`Trend(${wt.confidence.toFixed(0)}%)`);
    }

    const md = meanDeviation(vals);
    if (md) {
        if (md.prediction === "t") sT += md.confidence / 40; else sX += md.confidence / 40;
        algos.push(`Deviation(${md.confidence.toFixed(0)}%)`);
    }

    const cycle = detectCycle(vals);
    if (cycle && cycle.correlation > 0.3) {
        if (cycle.prediction === "t") sT += 2.0; else sX += 2.0;
        algos.push(`Cycle(${cycle.period}:${cycle.correlation.toFixed(2)})`);
    }

    const mk = markovPredict(vals);
    if (mk) {
        const mw = mk.confidence / 30;
        if (mk.prediction === "t") sT += mw; else sX += mw;
        algos.push(`Markov(B${mk.order}:${mk.confidence}%)`);
    }

    const fm = fibonacciMomentum(vals);
    if (fm) {
        if (fm.prediction === "t") sT += 1.5; else sX += 1.5;
        algos.push(`Fibonacci(${fm.confidence.toFixed(0)}%)`);
    }

    const bb = smartBridgeBreak(vals);
    if (bb && streak >= 3) {
        if (bb.prediction === "t") sT += 2.5; else sX += 2.5;
        algos.push(`BridgeBreak(${(bb.breakProb * 100).toFixed(0)}%)`);
    }

    const pdb = patternDBLookup(vals);
    if (pdb) {
        if (pdb.prediction === "t") sT += 2.0; else sX += 2.0;
        algos.push(`PatternDB(${pdb.pattern})`);
    }

    const sp = detectSpecialPatterns(vals);
    if (sp) {
        if (sp.prediction === "t") sT += 1.5; else sX += 1.5;
        algos.push(`Special(${sp.pattern})`);
    }

    const last20 = vals.slice(-20);
    const t20 = last20.filter(v => v === "t").length;
    if (t20 >= 14) sX += 0.5;
    else if (t20 <= 6) sT += 0.5;

    const total = (sT + sX) || 1;
    const val = sT >= sX ? "t" : "x";
    const winScore = Math.max(sT, sX);
    const conf = Math.min(95, Math.max(55, Math.round((winScore / total) * 100)));

    return {
        val,
        conf,
        algos: algos.slice(0, 8),
        prob_t: +(sT / total).toFixed(4),
        prob_x: +(sX / total).toFixed(4),
        streak,
        pattern: streak >= 2 ? (`Bệt ${last} ×${streak}`) : (sp ? sp.pattern : (pdb ? pdb.pattern : "")),
    };
}

// ============================================================================
// PHẦN 2: KIẾN TRÚC 5 LÕI THUẬT TOÁN MỚI HOÀN TOÀN v3.0 (KHÔNG TRÙNG LẶP)
// ============================================================================
function sideLabel(side) {
    if (side === "TAI" || side === "T") return "Tài";
    if (side === "XIU" || side === "X") return "Xỉu";
    return "Không rõ";
}

function oppositeSide(side) {
    return (side === "TAI" || side === "T") ? "XIU" : "TAI";
}

function clamp(v, lo, hi) {
    return Math.max(lo, Math.min(hi, v));
}

function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

function buildRunTimeline(chrono) {
    const runs = [];
    for (const r of chrono) {
        const side = r.tx === "T" ? "TAI" : "XIU";
        const sum = Number.isInteger(r.total) ? r.total : null;
        if (runs.length && runs[runs.length - 1].side === side) {
            const cur = runs[runs.length - 1];
            cur.length += 1;
            if (sum !== null) cur.sums.push(sum);
        } else {
            runs.push({
                side,
                length: 1,
                sums: sum !== null ? [sum] : [],
            });
        }
    }
    return runs;
}

function computeStreakSurvivalStats(runsAll) {
    const completed = runsAll.slice(0, -1);
    if (completed.length < 5) {
        return { s2to3: 0.48, s3to4: 0.48, s4to5: 0.42, s5to6: 0.35, maxRun: 5 };
    }
    const c2 = completed.filter(r => r.length >= 2).length;
    const c3 = completed.filter(r => r.length >= 3).length;
    const c4 = completed.filter(r => r.length >= 4).length;
    const c5 = completed.filter(r => r.length >= 5).length;
    const c6 = completed.filter(r => r.length >= 6).length;
    const maxRun = completed.reduce((m, r) => Math.max(m, r.length), 1);
    return {
        s2to3: (c3 + 1.0) / (c2 + 2.0),
        s3to4: (c4 + 0.9) / (c3 + 1.8),
        s4to5: (c5 + 0.8) / (c4 + 1.6),
        s5to6: (c6 + 0.6) / (c5 + 1.4),
        maxRun,
    };
}

// ----------------------------------------------------------------------------
// LÕI 1: STRUCTURAL BRIDGE & INFLECTION ENGINE
// Bắt nhịp cầu cấu trúc đa tầng, quyết định THEO CẦU vs BẺ CẦU theo năng lượng hạt
// ----------------------------------------------------------------------------
const SYMMETRIC_TEMPLATES = [
    ["1-2-3", [1, 2, 3]],
    ["3-2-1", [3, 2, 1]],
    ["3-2-3", [3, 2, 3]],
    ["4-2-4", [4, 2, 4]],
    ["2-3-2", [2, 3, 2]],
    ["2-4-2", [2, 4, 2]],
    ["3-1-3", [3, 1, 3]],
    ["1-3-1", [1, 3, 1]],
    ["4-1-4", [4, 1, 4]],
    ["1-4-1", [1, 4, 1]],
    ["2-1-2", [2, 1, 2]],
    ["1-2-1", [1, 2, 1]],
];

function coreStructuralBridgeTracker(recent20, chronoAll) {
    if (recent20.length < 4) {
        return {
            name: "Đang dò cầu",
            category: "UNKNOWN",
            action: "NEUTRAL",
            quality: "NEUTRAL",
            pred_side: null,
            prob_tai: 0.5,
            strength: 0,
            streak: 0,
            border_hits: 0,
        };
    }

    const runs20 = buildRunTimeline(recent20);
    const runsAll = buildRunTimeline(chronoAll);
    const lens = runs20.map(r => r.length);
    const curRun = runs20[runs20.length - 1];
    const curSide = curRun.side;
    const curLen = curRun.length;
    const opp = oppositeSide(curSide);
    const curSums = curRun.sums;
    const borderHits = curSums.filter(s => s === 10 || s === 11).length;
    const lastSum = curSums.length ? curSums[curSums.length - 1] : null;
    const prevSum = curSums.length >= 2 ? curSums[curSums.length - 2] : null;
    const survival = computeStreakSurvivalStats(runsAll);

    // Kiểm tra năng lượng điểm số của chuỗi hiện tại (tăng lực hay suy kiệt về 10-11)
    const highEnergy = lastSum !== null && (
        (curSide === "TAI" && lastSum >= 13) ||
        (curSide === "XIU" && lastSum <= 8)
    );
    const decayingEnergy = (
        borderHits >= 2 ||
        (lastSum !== null && prevSum !== null && (
            (curSide === "TAI" && lastSum <= 11 && prevSum > lastSum) ||
            (curSide === "XIU" && lastSum >= 10 && prevSum < lastSum)
        ))
    );

    // 1. Cầu Bệt (curLen >= 3): Phân định rõ THEO BỆT vs BẺ BỆT
    if (curLen >= 3) {
        if (curLen === 3) {
            if (decayingEnergy || (survival.s3to4 < 0.40 && !highEnergy)) {
                return {
                    name: `Bệt ${sideLabel(curSide)} 3 tay (suy lực)`,
                    category: "BET_BE",
                    action: "BE",
                    quality: borderHits <= 1 ? "DEP" : "XAU",
                    pred_side: opp,
                    prob_tai: opp === "TAI" ? 0.69 : 0.31,
                    strength: 0.78,
                    streak: 3,
                    border_hits: borderHits,
                };
            }
            if (borderHits === 0 && (highEnergy || survival.s3to4 >= 0.46)) {
                return {
                    name: `Bệt ${sideLabel(curSide)} 3 tay (lực mạnh)`,
                    category: "BET_THEO",
                    action: "THEO",
                    quality: "DEP",
                    pred_side: curSide,
                    prob_tai: curSide === "TAI" ? 0.71 : 0.29,
                    strength: 0.82,
                    streak: 3,
                    border_hits: borderHits,
                };
            }
        } else if (curLen === 4 || curLen === 5) {
            const survRate = curLen === 4 ? survival.s4to5 : survival.s5to6;
            if (!decayingEnergy && borderHits === 0 && highEnergy && survRate >= 0.42 && curLen < survival.maxRun) {
                return {
                    name: `Bệt thông ${sideLabel(curSide)} (${curLen} tay)`,
                    category: "BET_THEO",
                    action: "THEO",
                    quality: "DEP",
                    pred_side: curSide,
                    prob_tai: curSide === "TAI" ? 0.70 : 0.30,
                    strength: 0.80,
                    streak: curLen,
                    border_hits: borderHits,
                };
            }
            return {
                name: `Bệt ${sideLabel(curSide)} ${curLen} tay (chạm đỉnh)`,
                category: "BET_BE",
                action: "BE",
                quality: "DEP",
                pred_side: opp,
                prob_tai: opp === "TAI" ? 0.71 : 0.29,
                strength: 0.84,
                streak: curLen,
                border_hits: borderHits,
            };
        } else {
            // Bệt >= 6 tay: xác suất gãy rất cao -> Bẻ cầu dứt khoát
            const pBreak = clamp(0.70 + (curLen - 6) * 0.025, 0.70, 0.82);
            return {
                name: `Bệt già ${sideLabel(curSide)} (${curLen} tay)`,
                category: "BET_BE",
                action: "BE",
                quality: "DEP",
                pred_side: opp,
                prob_tai: opp === "TAI" ? pBreak : (1 - pBreak),
                strength: 0.90,
                streak: curLen,
                border_hits: borderHits,
            };
        }
    }

    // 2. Cầu 3-3 chuẩn (cả đang nối và đã đủ cặp)
    if (lens.length >= 2) {
        const l2 = lens.slice(-2);
        const l3 = lens.length >= 3 ? lens.slice(-3) : [];
        if (l3.length === 3 && l3[0] === 3 && l3[1] === 3 && (l3[2] === 1 || l3[2] === 2)) {
            return {
                name: `Cầu 3-3 (nhịp 3 · tay ${l3[2]}/3)`,
                category: "CAU_33",
                action: "THEO",
                quality: borderHits === 0 ? "DEP" : "XAU",
                pred_side: curSide,
                prob_tai: curSide === "TAI" ? 0.72 : 0.28,
                strength: 0.85,
                streak: 6 + l3[2],
                border_hits: borderHits,
            };
        }
        if (l2[0] === 3 && (l2[1] === 1 || l2[1] === 2)) {
            const prevPrev = lens.length >= 3 ? lens[lens.length - 3] : 0;
            if (prevPrev !== 1 && prevPrev !== 2) {
                return {
                    name: `Cầu 3-3 (tay ${l2[1]}/3)`,
                    category: "CAU_33",
                    action: "THEO",
                    quality: borderHits === 0 ? "DEP" : "XAU",
                    pred_side: curSide,
                    prob_tai: curSide === "TAI" ? 0.69 : 0.31,
                    strength: 0.76,
                    streak: 3 + l2[1],
                    border_hits: borderHits,
                };
            }
        }
        if (l2[0] === 3 && l2[1] === 3) {
            return {
                name: "Cầu 3-3 (chốt cặp)",
                category: "CAU_33",
                action: "BE",
                quality: borderHits <= 1 ? "DEP" : "XAU",
                pred_side: opp,
                prob_tai: opp === "TAI" ? 0.71 : 0.29,
                strength: 0.82,
                streak: 6,
                border_hits: borderHits,
            };
        }
    }

    // 3. Cầu 2-2 chuẩn (xử lý trọn vẹn cả đang lên cặp [2,2,1] và chốt cặp [2,2])
    if (lens.length >= 2) {
        if (curLen === 1 && lens.length >= 3) {
            let priorTwos = 0;
            for (let i = lens.length - 2; i >= 0; i--) {
                if (lens[i] === 2) priorTwos++;
                else break;
            }
            if (priorTwos >= 2 && priorTwos <= 3) {
                return {
                    name: `Cầu 2-2 (cặp ${priorTwos + 1} · tay 1/2)`,
                    category: "CAU_22",
                    action: "THEO",
                    quality: borderHits === 0 ? "DEP" : "XAU",
                    pred_side: curSide,
                    prob_tai: curSide === "TAI" ? 0.72 : 0.28,
                    strength: 0.85,
                    streak: priorTwos * 2 + 1,
                    border_hits: borderHits,
                };
            }
        }
        let trailingTwos = 0;
        for (let i = lens.length - 1; i >= 0; i--) {
            if (lens[i] === 2) trailingTwos++;
            else break;
        }
        if (trailingTwos >= 2) {
            if (trailingTwos <= 3) {
                return {
                    name: `Cầu 2-2 (${trailingTwos} cặp · Đẹp)`,
                    category: "CAU_22",
                    action: "BE",
                    quality: borderHits === 0 ? "DEP" : "XAU",
                    pred_side: opp,
                    prob_tai: opp === "TAI" ? 0.71 : 0.29,
                    strength: 0.84,
                    streak: trailingTwos * 2,
                    border_hits: borderHits,
                };
            }
            return {
                name: `Cầu 2-2 (${trailingTwos} cặp · Bẻ nhịp)`,
                category: "CAU_22",
                action: "THEO",
                quality: "XAU",
                pred_side: curSide,
                prob_tai: curSide === "TAI" ? 0.65 : 0.35,
                strength: 0.68,
                streak: trailingTwos * 2,
                border_hits: borderHits,
            };
        }
    }

    // 4. Cầu 1-1 chuẩn (tính chính xác số nhịp xen kẽ liên tiếp ở cuối)
    let altLen = 1;
    for (let i = recent20.length - 1; i >= 1; i--) {
        if (recent20[i].tx !== recent20[i - 1].tx) altLen++;
        else break;
    }
    if (altLen >= 4) {
        if (altLen <= 6 && borderHits === 0) {
            return {
                name: `Cầu 1-1 (${altLen} nhịp · Đẹp)`,
                category: "CAU_11",
                action: "THEO",
                quality: "DEP",
                pred_side: opp,
                prob_tai: opp === "TAI" ? 0.72 : 0.28,
                strength: 0.85,
                streak: altLen,
                border_hits: borderHits,
            };
        }
        return {
            name: `Cầu 1-1 (${altLen} nhịp · Bẻ cầu)`,
            category: "CAU_11",
            action: "BE",
            quality: altLen >= 7 ? "DEP" : "XAU",
            pred_side: curSide,
            prob_tai: curSide === "TAI" ? 0.68 : 0.32,
            strength: 0.76,
            streak: altLen,
            border_hits: borderHits,
        };
    }

    // 5. Cầu Nghiêng / Cầu 1 Chân (1 cửa chạy chuỗi 2-5 tay, cửa kia chỉ 1 tay rồi gãy)
    if (runs20.length >= 5) {
        const tailRuns = runs20.slice(-6);
        const tLens = tailRuns.filter(r => r.side === "TAI").map(r => r.length);
        const xLens = tailRuns.filter(r => r.side === "XIU").map(r => r.length);
        if (tLens.length >= 2 && xLens.length >= 2) {
            const avgT = tLens.reduce((a, b) => a + b, 0) / tLens.length;
            const avgX = xLens.reduce((a, b) => a + b, 0) / xLens.length;
            if (avgT >= 2.4 && avgX <= 1.25) {
                if (curSide === "XIU" && curLen === 1) {
                    return {
                        name: "Cầu nghiêng Tài (1 chân Xỉu)",
                        category: "CAU_NGHIENG",
                        action: "BE",
                        quality: "DEP",
                        pred_side: "TAI",
                        prob_tai: 0.72,
                        strength: 0.84,
                        streak: 1,
                        border_hits: borderHits,
                    };
                }
                if (curSide === "TAI" && curLen <= 2) {
                    return {
                        name: `Cầu nghiêng Tài (tay ${curLen})`,
                        category: "CAU_NGHIENG",
                        action: "THEO",
                        quality: "DEP",
                        pred_side: "TAI",
                        prob_tai: 0.69,
                        strength: 0.78,
                        streak: curLen,
                        border_hits: borderHits,
                    };
                }
            } else if (avgX >= 2.4 && avgT <= 1.25) {
                if (curSide === "TAI" && curLen === 1) {
                    return {
                        name: "Cầu nghiêng Xỉu (1 chân Tài)",
                        category: "CAU_NGHIENG",
                        action: "BE",
                        quality: "DEP",
                        pred_side: "XIU",
                        prob_tai: 0.28,
                        strength: 0.84,
                        streak: 1,
                        border_hits: borderHits,
                    };
                }
                if (curSide === "XIU" && curLen <= 2) {
                    return {
                        name: `Cầu nghiêng Xỉu (tay ${curLen})`,
                        category: "CAU_NGHIENG",
                        action: "THEO",
                        quality: "DEP",
                        pred_side: "XIU",
                        prob_tai: 0.31,
                        strength: 0.78,
                        streak: curLen,
                        border_hits: borderHits,
                    };
                }
            }
        }
    }

    // 6. Mẫu cầu đối xứng & tiến lùi (1-2-1, 2-1-2, 1-2-3, 3-2-1, 3-2-3...)
    for (const [tplName, tpl] of SYMMETRIC_TEMPLATES) {
        const m = tpl.length;
        if (lens.length >= m) {
            const tail = lens.slice(-m);
            if (arraysEqual(tail.slice(0, -1), tpl.slice(0, -1)) && tail[m - 1] < tpl[m - 1]) {
                return {
                    name: `Cầu ${tplName} (tay ${tail[m - 1]}/${tpl[m - 1]})`,
                    category: "TEMPLATE",
                    action: "THEO",
                    quality: borderHits <= 1 ? "DEP" : "XAU",
                    pred_side: curSide,
                    prob_tai: curSide === "TAI" ? 0.70 : 0.30,
                    strength: 0.80,
                    streak: curLen,
                    border_hits: borderHits,
                };
            }
            if (arraysEqual(tail, tpl)) {
                return {
                    name: `Cầu ${tplName} (đủ nhịp)`,
                    category: "TEMPLATE",
                    action: "BE",
                    quality: borderHits <= 1 ? "DEP" : "XAU",
                    pred_side: opp,
                    prob_tai: opp === "TAI" ? 0.70 : 0.30,
                    strength: 0.80,
                    streak: curLen,
                    border_hits: borderHits,
                };
            }
        }
    }

    const tailStr = lens.slice(-3).join("-");
    return {
        name: `Nhịp tự do [${tailStr}]`,
        category: "FREE",
        action: "NEUTRAL",
        quality: borderHits >= 2 ? "XAU" : "NEUTRAL",
        pred_side: null,
        prob_tai: 0.5,
        strength: 0,
        streak: curLen,
        border_hits: borderHits,
    };
}

// ----------------------------------------------------------------------------
// LÕI 2: DICE PHYSICS & POINT TRAJECTORY ENGINE (HOÀN TOÀN MỚI)
// Phân tích động lực học 3 hạt xúc xắc, EMA điểm số, vận tốc điểm & bộ hạt trùng
// ----------------------------------------------------------------------------
function coreDicePhysicsAndMomentum(recent20, chronoAll) {
    const n20 = recent20.length;
    if (n20 < 5) {
        return { prob_tai: 0.5, pred_side: null, strength: 0, note: "XX: chờ dữ liệu", has_exact: false };
    }

    const sums = recent20.map(r => r.total);
    const latest = recent20[n20 - 1];
    const latestSum = latest.total;

    // 1. EMA ngắn hạn (3 phiên) và trung hạn (8 phiên) quanh trục 10.5
    let ema3 = sums[0];
    let ema8 = sums[0];
    for (let i = 1; i < n20; i++) {
        ema3 = 0.50 * sums[i] + 0.50 * ema3;
        ema8 = 0.22 * sums[i] + 0.78 * ema8;
    }
    const centerBias = (ema3 - 10.5) / 7.5;     // [-1, +1]
    const velocityBias = (ema3 - ema8) / 6.0;    // [-1, +1]

    // 2. Tỷ lệ mặt hạt lớn [4,5,6] vs mặt hạt nhỏ [1,2,3] trong 5 phiên gần nhất
    const last5 = recent20.slice(-5);
    let highPips = 0, lowPips = 0;
    for (const r of last5) {
        if (Array.isArray(r.dice) && r.dice.length === 3) {
            for (const d of r.dice) {
                if (d >= 4) highPips++;
                else lowPips++;
            }
        }
    }
    const pipBias = (highPips + lowPips) > 0
        ? (highPips - lowPips) / (highPips + lowPips)
        : 0;

    // 3. Đối chiếu điểm số & bộ 3 hạt trùng khớp (20p ưu tiên + 200p làm nền)
    let histNum = 0, histDen = 0, exactSamples = 0;
    const notes = [];

    if (Number.isInteger(latestSum)) {
        let t20 = 0, x20 = 0, c20 = 0;
        for (let i = 0; i < n20 - 1; i++) {
            if (recent20[i].total === latestSum) {
                const dist = (n20 - 1) - i;
                const w = Math.exp(-0.12 * (dist - 1));
                c20++;
                if (recent20[i + 1].tx === "T") t20 += w;
                else x20 += w;
            }
        }
        if (c20 >= 1) {
            const p20 = (t20 + 1.3) / (t20 + x20 + 2.6);
            const w20 = c20 >= 2 ? 2.2 : 1.0;
            histNum += p20 * w20;
            histDen += w20;
            if (c20 >= 2) exactSamples += c20;
            notes.push(`Điểm ${latestSum}: ${Math.round(t20 * 10) / 10}T/${Math.round(x20 * 10) / 10}X`);
        }

        if (chronoAll.length > 25) {
            let tAll = 0, xAll = 0, cAll = 0;
            for (let i = 0; i < chronoAll.length - 1; i++) {
                if (chronoAll[i].total === latestSum) {
                    const dist = (chronoAll.length - 1) - i;
                    const w = Math.exp(-0.02 * dist);
                    cAll++;
                    if (chronoAll[i + 1].tx === "T") tAll += w;
                    else xAll += w;
                }
            }
            if (cAll >= 3) {
                const pAll = (tAll + 2.0) / (tAll + xAll + 4.0);
                histNum += pAll * 1.8;
                histDen += 1.8;
            }
        }
    }

    if (Array.isArray(latest.dice) && latest.dice.length === 3) {
        const sig = [...latest.dice].sort((a, b) => a - b).join("-");
        let td = 0, xd = 0, cd = 0;
        for (let i = 0; i < chronoAll.length - 1; i++) {
            const di = chronoAll[i].dice;
            if (Array.isArray(di) && di.length === 3 && [...di].sort((a, b) => a - b).join("-") === sig) {
                const dist = (chronoAll.length - 1) - i;
                const w = dist <= 20 ? 1.5 : Math.exp(-0.025 * dist);
                cd++;
                if (chronoAll[i + 1].tx === "T") td += w;
                else xd += w;
            }
        }
        if (cd >= 2) {
            const pDice = (td + 1.2) / (td + xd + 2.4);
            histNum += pDice * 1.6;
            histDen += 1.6;
            exactSamples += cd;
            notes.push(`Hạt [${sig}]: ${cd} mẫu`);
        }
    }

    const physProbTai = clamp(0.5 + 0.16 * centerBias + 0.12 * velocityBias + 0.10 * pipBias, 0.25, 0.75);
    const histProbTai = histDen > 0 ? (histNum / histDen) : 0.5;
    const combinedPTai = histDen > 0
        ? (0.55 * physProbTai + 0.45 * histProbTai)
        : physProbTai;

    const edge = Math.abs(combinedPTai - 0.5);
    const predSide = edge >= 0.045 ? (combinedPTai > 0.5 ? "TAI" : "XIU") : null;
    const noteStr = notes.length
        ? notes.slice(0, 2).join(" · ")
        : `EMA ${ema3.toFixed(1)}đ · Hạt ${highPips}L/${lowPips}N`;

    return {
        prob_tai: combinedPTai,
        pred_side: predSide,
        strength: clamp(edge * 4.5, 0, 1),
        note: noteStr,
        has_exact: exactSamples >= 2,
    };
}

// ----------------------------------------------------------------------------
// LÕI 3: MULTI-SCALE TABLE REGIME DETECTOR (BỘ NHẬN DIỆN TRẠNG THÁI BÀN)
// Phân biệt rõ: Bàn Bệt (Trend) / Bàn Nhảy Nhịp (Chop) / Bàn Lệch Cực Đại
// ----------------------------------------------------------------------------
function coreMultiScaleRegimeDetector(recent20, chronoAll) {
    if (recent20.length < 8) {
        return {
            regime: "INIT",
            flipRate: 0.5,
            prob_tai: 0.5,
            pred_side: null,
            strength: 0,
            tag: "",
        };
    }

    const last12 = recent20.slice(-12);
    let flips12 = 0;
    for (let i = 1; i < last12.length; i++) {
        if (last12[i].tx !== last12[i - 1].tx) flips12++;
    }
    const flipRate = flips12 / (last12.length - 1);

    const lastSide = recent20[recent20.length - 1].tx === "T" ? "TAI" : "XIU";
    const oppSide = oppositeSide(lastSide);

    const t20 = recent20.filter(r => r.tx === "T").length;
    const x20 = recent20.length - t20;
    const imbalance20 = (t20 - x20) / recent20.length; // [-1, +1]

    // Trường hợp 1: Lệch cửa cực đại trong 20 phiên (>= 15/5 hoặc <= 5/15) -> Hồi quy cân bằng
    if (Math.abs(imbalance20) >= 0.50) {
        const revSide = imbalance20 > 0 ? "XIU" : "TAI";
        const pT = revSide === "TAI" ? 0.66 : 0.34;
        return {
            regime: "EXTREME_IMBALANCE",
            flipRate,
            prob_tai: pT,
            pred_side: revSide,
            strength: 0.75,
            tag: `LệchCựcĐại(${t20}T/${x20}X)`,
        };
    }

    // Trường hợp 2: Bàn Bệt / Xu hướng mạnh (flipRate <= 0.36) -> Đánh thuận dòng chảy
    if (flipRate <= 0.36) {
        const pT = lastSide === "TAI" ? 0.66 : 0.34;
        return {
            regime: "TREND_BET",
            flipRate,
            prob_tai: pT,
            pred_side: lastSide,
            strength: 0.72,
            tag: `BànBệt(${Math.round((1 - flipRate) * 100)}%)`,
        };
    }

    // Trường hợp 3: Bàn Nhảy Nhịp / Đảo liên tục (flipRate >= 0.64) -> Đánh đảo chiều
    if (flipRate >= 0.64) {
        const pT = oppSide === "TAI" ? 0.66 : 0.34;
        return {
            regime: "CHOP_11",
            flipRate,
            prob_tai: pT,
            pred_side: oppSide,
            strength: 0.72,
            tag: `BànNhảy(${Math.round(flipRate * 100)}%)`,
        };
    }

    return {
        regime: "MIXED",
        flipRate,
        prob_tai: 0.5,
        pred_side: null,
        strength: 0,
        tag: "",
    };
}

// ----------------------------------------------------------------------------
// LÕI 4: VARIABLE-ORDER CONTEXT & RUN-TRANSITION MATCHER (THAY THẾ N-GRAM/MARKOV CŨ)
// Khớp đồng thời chuỗi kết quả (bậc 2->5) và chuỗi độ dài nhịp (bậc 2->3)
// ----------------------------------------------------------------------------
function coreSequenceContextMatcher(chronoAll) {
    const n = chronoAll.length;
    if (n < 10) {
        return { prob_tai: 0.5, pred_side: null, strength: 0, tag: "" };
    }

    const vals = chronoAll.map(r => r.tx === "T" ? "t" : "x");
    let numT = 0, denW = 0, bestTag = "", bestEdge = 0;

    // A. Khớp chuỗi ký hiệu T/X bậc 2 -> 5 có trọng số suy giảm thời gian
    for (let len = 2; len <= 5; len++) {
        if (n < len + 4) continue;
        const target = vals.slice(-len).join("");
        let tw = 0, xw = 0, hits = 0;
        for (let i = 0; i < n - len; i++) {
            if (vals.slice(i, i + len).join("") === target) {
                const age = (n - len) - i;
                const rec = Math.exp(-0.025 * age);
                hits++;
                if (vals[i + len] === "t") tw += rec;
                else xw += rec;
            }
        }
        if (hits >= 3) {
            const pT = (tw + 1.2) / (tw + xw + 2.4);
            const edge = Math.abs(pT - 0.5);
            if (edge >= 0.05) {
                const w = (0.7 + len * 0.35) * (edge * 2);
                numT += pT * w;
                denW += w;
                if (edge > bestEdge) {
                    bestEdge = edge;
                    bestTag = `NgữCảnh${len}(${Math.round(Math.max(pT, 1 - pT) * 100)}%)`;
                }
            }
        }
    }

    // B. Khớp chuỗi độ dài nhịp (Run-Length Transition): ví dụ [3, 1] hay [2, 2] trong quá khứ hay đi tiếp thế nào
    const runs = buildRunTimeline(chronoAll);
    if (runs.length >= 6) {
        const curRun = runs[runs.length - 1];
        const prevRun = runs[runs.length - 2];
        let contW = 0, flipW = 0, runHits = 0;
        for (let i = 1; i < runs.length - 1; i++) {
            if (runs[i - 1].length === prevRun.length && runs[i].length >= curRun.length) {
                const age = (runs.length - 1) - i;
                const rec = Math.exp(-0.08 * age);
                runHits++;
                if (runs[i].length > curRun.length) contW += rec;
                else flipW += rec;
            }
        }
        if (runHits >= 3) {
            const pCont = (contW + 1.0) / (contW + flipW + 2.0);
            const pT = curRun.side === "TAI" ? pCont : (1 - pCont);
            const edge = Math.abs(pT - 0.5);
            if (edge >= 0.05) {
                const w = 1.4 * (edge * 2);
                numT += pT * w;
                denW += w;
                if (edge > bestEdge) {
                    bestEdge = edge;
                    bestTag = `Nhịp[${prevRun.length}-${curRun.length}](${runHits}m)`;
                }
            }
        }
    }

    if (denW <= 1e-6) {
        return { prob_tai: 0.5, pred_side: null, strength: 0, tag: "" };
    }

    const finalPT = numT / denW;
    const edge = Math.abs(finalPT - 0.5);
    const predSide = edge >= 0.045 ? (finalPT > 0.5 ? "TAI" : "XIU") : null;
    return {
        prob_tai: finalPT,
        pred_side: predSide,
        strength: clamp(edge * 4.5, 0, 1),
        tag: predSide ? bestTag : "",
    };
}

// ============================================================================
// PHẦN 3: BỘ NÃO TRUNG TÂM SUPER HYBRID AI ENGINE v3.0 (5 LÕI ĐỘC LẬP)
// ============================================================================
class SuperHybridAIEngine {
    constructor() {
        this.baseWeights = {
            bridge: 2.10,
            dice_physics: 1.45,
            regime: 1.30,
            context: 1.15,
        };
        this.weights = { ...this.baseWeights };
        this.coreHitWindow = {
            bridge: [],
            dice_physics: [],
            regime: [],
            context: [],
        };
        this.lastModelPreds = null;
        this.lastDirectSide = null;
        this.directWindow = [];     // 1 = Thuận nhịp thắng, 0 = Thuận nhịp thua
        this.contrarianWindow = []; // 1 = Đảo nhịp thắng, 0 = Đảo nhịp thua
        this.consecutiveLosses = 0;
        this.phaseInverted = false;
        this.calibrated = false;
    }

    _updateCoreWeights() {
        for (const [key, baseW] of Object.entries(this.baseWeights)) {
            const arr = this.coreHitWindow[key] || [];
            if (arr.length < 3) {
                this.weights[key] = baseW;
                continue;
            }
            let wHit = 0, wTot = 0;
            for (let i = 0; i < arr.length; i++) {
                const rec = Math.pow(1.12, i);
                wTot += rec;
                if (arr[i] === 1) wHit += rec;
            }
            const acc = wHit / Math.max(1e-6, wTot);
            // Tự thưởng mạnh lõi đang bắt trúng bàn (acc >= 0.65 -> 1.65x), hạ thấp lõi đang sai (acc <= 0.30 -> 0.30x)
            const mult = clamp(0.25 + Math.pow(acc / 0.50, 1.75) * 0.75, 0.25, 1.85);
            this.weights[key] = +(baseW * mult).toFixed(4);
        }
    }

    _recordCoreFeedback(actualSide, modelPreds) {
        if (!modelPreds) return;
        for (const [key, predSide] of Object.entries(modelPreds)) {
            if ((predSide === "TAI" || predSide === "XIU") && this.coreHitWindow[key]) {
                const hit = predSide === actualSide ? 1 : 0;
                this.coreHitWindow[key].push(hit);
                if (this.coreHitWindow[key].length > 12) {
                    this.coreHitWindow[key].shift();
                }
            }
        }
        this._updateCoreWeights();
    }

    updateActual(actualTx, predictedTx = null) {
        const actualSide = actualTx === "T" ? "TAI" : "XIU";

        if (this.lastDirectSide === "TAI" || this.lastDirectSide === "XIU") {
            const directWon = this.lastDirectSide === actualSide ? 1 : 0;
            this.directWindow.push(directWon);
            this.contrarianWindow.push(1 - directWon);
            if (this.directWindow.length > 8) this.directWindow.shift();
            if (this.contrarianWindow.length > 8) this.contrarianWindow.shift();
            this.lastDirectSide = null;
        }

        if (predictedTx === "T" || predictedTx === "X") {
            if (predictedTx === actualTx) {
                this.consecutiveLosses = 0;
            } else {
                this.consecutiveLosses += 1;
            }
        }

        // Quản lý trạng thái Đảo Nhịp thông minh dựa trên hiệu suất đối chiếu thực tế 8 phiên
        if (this.directWindow.length >= 5) {
            const dAcc = this.directWindow.reduce((a, b) => a + b, 0) / this.directWindow.length;
            const cAcc = this.contrarianWindow.reduce((a, b) => a + b, 0) / this.contrarianWindow.length;
            if (!this.phaseInverted) {
                if (this.consecutiveLosses >= 3 && cAcc >= 0.65 && dAcc <= 0.35) {
                    this.phaseInverted = true;
                }
            } else {
                // Thoát ngay khi chế độ Đảo Nhịp gãy 2 tay hoặc Thuận Nhịp phục hồi >= 50%
                if (this.consecutiveLosses >= 2 || dAcc >= 0.50) {
                    this.phaseInverted = false;
                }
            }
        }

        if (this.lastModelPreds) {
            this._recordCoreFeedback(actualSide, this.lastModelPreds);
            this.lastModelPreds = null;
        }
    }

    warmStartCalibrate(chronoAll) {
        if (this.calibrated || chronoAll.length < 25) return;
        const startIdx = Math.max(15, chronoAll.length - 25);
        const phaseStartIdx = Math.max(startIdx, chronoAll.length - 8);
        for (let i = startIdx; i < chronoAll.length; i++) {
            const sub = chronoAll.slice(0, i);
            const res = this._computeRaw(sub, false);
            const actualTx = chronoAll[i].tx;
            const actualSide = actualTx === "T" ? "TAI" : "XIU";
            this._recordCoreFeedback(actualSide, res.modelPreds);
            if (i >= phaseStartIdx) {
                this.lastDirectSide = res._directSide;
                this.updateActual(actualTx, res.rawPrediction);
            }
        }
        this.calibrated = true;
    }

    _computeRaw(chronoAll, recordState = true) {
        const chrono = chronoAll.slice(-MAX_STORE_ROUNDS);
        const latest = chrono[chrono.length - 1];
        const recent20 = chrono.slice(-WINDOW_20_ROUNDS);
        const valsAll = chrono.map(r => (r.tx === "T" ? "t" : "x"));

        // Bảo vệ khởi động lạnh (< 5 phiên)
        if (chrono.length < 5) {
            const si = detectStreak(valsAll);
            const pick = si.streak >= 3
                ? (si.current === "t" ? "x" : "t")
                : (si.streak === 2 ? si.current : (valsAll[valsAll.length - 1] === "t" ? "x" : "t"));
            const rawPred = pick.toUpperCase();
            return {
                prediction: rawPred === "T" ? "tai" : "xiu",
                rawPrediction: rawPred,
                confidence: 55,
                tai_pct: rawPred === "T" ? 55 : 45,
                xiu_pct: rawPred === "X" ? 55 : 45,
                prob_t: rawPred === "T" ? 0.55 : 0.45,
                prob_x: rawPred === "X" ? 0.55 : 0.45,
                score_t: rawPred === "T" ? 1.1 : 0.9,
                score_x: rawPred === "X" ? 1.1 : 0.9,
                streak: si.streak || 0,
                pattern: valsAll.join(""),
                bridge_name: "Đang gom dữ liệu",
                is_too_bad: false,
                advice_status: "⏳ Đang gom đủ 5 phiên",
                algos: [`Khởi động (${chrono.length}/5 phiên)`],
                modelPreds: {},
                _directSide: rawPred === "T" ? "TAI" : "XIU",
            };
        }

        // Chạy 4 lõi phân tích trực giao hoàn toàn mới (không dùng lại thuật toán cũ)
        const bridgeCore = coreStructuralBridgeTracker(recent20, chrono);
        const diceCore = coreDicePhysicsAndMomentum(recent20, chrono);
        const regimeCore = coreMultiScaleRegimeDetector(recent20, chrono);
        const contextCore = coreSequenceContextMatcher(chrono);

        const coreOutputs = {
            bridge: bridgeCore,
            dice_physics: diceCore,
            regime: regimeCore,
            context: contextCore,
        };

        const modelPreds = {
            bridge: bridgeCore.pred_side || null,
            dice_physics: diceCore.pred_side || null,
            regime: regimeCore.pred_side || null,
            context: contextCore.pred_side || null,
        };

        // Điều phối trọng số động theo trạng thái bàn thực tế
        const effW = { ...this.weights };
        if (bridgeCore.pred_side && bridgeCore.quality === "DEP") {
            effW.bridge *= 1.45;
        } else if (bridgeCore.quality === "XAU") {
            effW.bridge *= 0.60;
        }

        if (regimeCore.regime === "TREND_BET") {
            // Khi bàn đang bệt mạnh, tăng trọng số cho cầu & động lực điểm số
            effW.bridge *= 1.20;
            effW.dice_physics *= 1.20;
        } else if (regimeCore.regime === "CHOP_11") {
            // Khi bàn đang nhảy 1-1, ưu tiên cầu cấu trúc & trạng thái bàn
            effW.bridge *= 1.25;
            effW.regime *= 1.20;
        }

        // Tổng hợp xác suất Bayesian từ các lõi có tín hiệu rõ ràng
        let numTai = 0, denW = 0, taiVoteW = 0, xiuVoteW = 0, activeCores = 0;
        for (const [k, out] of Object.entries(coreOutputs)) {
            if (out.pred_side === "TAI" || out.pred_side === "XIU") {
                const pT = Number(out.prob_tai ?? 0.5);
                const strengthBoost = 0.70 + 0.60 * Number(out.strength ?? 0.5);
                const w = (effW[k] || 1.0) * strengthBoost;
                numTai += w * pT;
                denW += w;
                activeCores++;
                if (out.pred_side === "TAI") taiVoteW += w;
                else xiuVoteW += w;
            }
        }

        let directPTai = denW > 0 ? (numTai / denW) : 0.5;
        directPTai = clamp(directPTai, 0.14, 0.86);

        let directSide;
        if (Math.abs(directPTai - 0.5) < 0.015) {
            directSide = bridgeCore.pred_side || diceCore.pred_side || regimeCore.pred_side || (latest.tx === "T" ? "XIU" : "TAI");
            directPTai = directSide === "TAI" ? 0.53 : 0.47;
        } else {
            directSide = directPTai > 0.5 ? "TAI" : "XIU";
        }

        // Áp dụng bộ điều khiển Đảo Pha nếu bàn đang bẻ ngược toàn bộ thuật toán thuận
        let finalPTai = this.phaseInverted ? (1.0 - directPTai) : directPTai;
        let predSide = this.phaseInverted ? oppositeSide(directSide) : directSide;

        let taiPct = Math.round(finalPTai * 100);
        if (taiPct === 50) taiPct = predSide === "TAI" ? 52 : 48;
        const xiuPct = 100 - taiPct;
        const confPct = predSide === "TAI" ? taiPct : xiuPct;

        const totVote = taiVoteW + xiuVoteW;
        const rawConsensus = totVote > 0
            ? (directSide === "TAI" ? taiVoteW : xiuVoteW) / totVote
            : 0.5;

        // Bộ lọc cầu xấu / bàn loạn (isTooBad)
        const border20 = recent20.filter(r => r.total === 10 || r.total === 11).length;
        const bridgeDiceConflict = (
            (bridgeCore.pred_side === "TAI" || bridgeCore.pred_side === "XIU") &&
            (diceCore.pred_side === "TAI" || diceCore.pred_side === "XIU") &&
            bridgeCore.pred_side !== diceCore.pred_side
        );

        let isTooBad = false;
        const badReasons = [];
        if (activeCores === 0) {
            isTooBad = true;
            badReasons.push("Chưa hình thành cầu, chờ nhịp");
        } else if (bridgeCore.quality === "XAU" && confPct < 63) {
            isTooBad = true;
            badReasons.push("Cầu chạm nút biên 10-11");
        } else if (border20 >= 6 && confPct < 64) {
            isTooBad = true;
            badReasons.push(`Bàn kẹt nút 10/11 (${border20}/20p)`);
        } else if (rawConsensus < 0.58 && confPct < 61) {
            isTooBad = true;
            badReasons.push("Các lõi đang phân tán");
        } else if (bridgeDiceConflict && confPct < 60) {
            isTooBad = true;
            badReasons.push("Nhịp cầu & xúc xắc lệch pha");
        } else if (confPct <= 55) {
            isTooBad = true;
            badReasons.push("Tín hiệu mỏng, đứng ngoài");
        }

        const actionLabel = this.phaseInverted
            ? "Đảo pha"
            : (bridgeCore.action === "BE" ? "Bẻ cầu" : (bridgeCore.action === "THEO" ? "Theo cầu" : "Động lực"));

        const adviceStatus = isTooBad
            ? `⚠️ CẦU XẤU - KHÔNG NÊN THEO (${badReasons[0]})`
            : `✅ CẦU ĐẸP [${actionLabel}] - CÓ THỂ THEO (${sideLabel(predSide)} · ${confPct}%)`;

        const algos = [
            `Cầu: ${bridgeCore.name}`,
            this.phaseInverted ? "🔄 ĐảoPha" : "",
            diceCore.note,
            regimeCore.tag,
            contextCore.tag,
            `Đồng thuận ${Math.round(rawConsensus * 100)}%`,
        ].filter(Boolean);

        if (recordState) {
            this.lastModelPreds = modelPreds;
            this.lastDirectSide = directSide;
        }

        const rawPred = predSide === "TAI" ? "T" : "X";
        return {
            prediction: rawPred === "T" ? "tai" : "xiu",
            rawPrediction: rawPred,
            confidence: confPct,
            tai_pct: taiPct,
            xiu_pct: xiuPct,
            prob_t: +(finalPTai).toFixed(4),
            prob_x: +(1 - finalPTai).toFixed(4),
            score_t: +taiVoteW.toFixed(2),
            score_x: +xiuVoteW.toFixed(2),
            streak: bridgeCore.streak || 0,
            pattern: valsAll.slice(-4).join(""),
            bridge_name: bridgeCore.name,
            is_too_bad: isTooBad,
            advice_status: adviceStatus,
            algos,
            modelPreds,
            _directSide: directSide,
        };
    }

    predict(chronoAll) {
        if (!this.calibrated && chronoAll.length >= 25) {
            this.warmStartCalibrate(chronoAll);
        }
        return this._computeRaw(chronoAll, true);
    }
}


// ============================================================================
// BỘ QUẢN LÝ NẠP / THAY THẾ THUẬT TOÁN ĐỘNG (.JS & .PY) & KHÔI PHỤC THUẬT TOÁN GỐC
// ============================================================================
const CUSTOM_ALGO_DIR = path.join(__dirname, "custom_algorithms");
const CUSTOM_ALGO_META = path.join(CUSTOM_ALGO_DIR, "active_algo.json");
const MAX_ALGO_FILE_BYTES = 1024 * 1024; // 1MB tối đa

function ensureCustomAlgoDir() {
    try {
        if (!fs.existsSync(CUSTOM_ALGO_DIR)) {
            fs.mkdirSync(CUSTOM_ALGO_DIR, { recursive: true });
        }
    } catch (_) {}
}

function detectPythonBinary() {
    const candidates = process.platform === "win32"
        ? ["python", "python3", "py"]
        : ["python3", "python"];
    for (const cmd of candidates) {
        try {
            const res = spawnSync(cmd, ["--version"], { encoding: "utf8", timeout: 2500 });
            if (res.status === 0) return cmd;
        } catch (_) {}
    }
    return null;
}

const PYTHON_BIN = detectPythonBinary();

function normalizeExternalPrediction(rawResult, history, fileName) {
    if (rawResult === null || rawResult === undefined) return null;

    let sideRaw = null;
    let confRaw = null;
    let taiPct = null;
    let xiuPct = null;
    let bridgeName = null;
    let adviceStatus = null;
    let isTooBad = false;
    let algos = [];

    if (typeof rawResult === "string") {
        sideRaw = rawResult.trim();
    } else if (typeof rawResult === "number") {
        if (rawResult === 1) sideRaw = "T";
        else if (rawResult === 0 || rawResult === 2) sideRaw = "X";
        else if (rawResult >= 11 && rawResult <= 18) sideRaw = "T";
        else if (rawResult >= 3 && rawResult <= 10) sideRaw = "X";
    } else if (typeof rawResult === "object") {
        sideRaw =
            rawResult.rawPrediction ??
            rawResult.du_doan ??
            rawResult.prediction ??
            rawResult.predict ??
            rawResult.side ??
            rawResult.ket_qua_du_doan ??
            rawResult.result ??
            rawResult.choice ??
            rawResult.pick ??
            rawResult.tx ??
            rawResult.signal ??
            (rawResult.data && (rawResult.data.du_doan || rawResult.data.prediction || rawResult.data.side));

        confRaw =
            rawResult.do_tin_cay ??
            rawResult.confidence ??
            rawResult.conf ??
            rawResult.ty_le ??
            rawResult.accuracy ??
            rawResult.prob ??
            (rawResult.data && (rawResult.data.do_tin_cay || rawResult.data.confidence));

        taiPct = rawResult.ty_le_tai ?? rawResult.tai_pct ?? null;
        xiuPct = rawResult.ty_le_xiu ?? rawResult.xiu_pct ?? null;
        bridgeName = rawResult.cau ?? rawResult.bridge_name ?? rawResult.pattern ?? rawResult.reason ?? null;
        adviceStatus = rawResult.khuyen_nghi ?? rawResult.advice_status ?? null;
        isTooBad = Boolean(rawResult.cau_xau ?? rawResult.is_too_bad ?? false);
        if (Array.isArray(rawResult.thuat_toan)) algos = rawResult.thuat_toan;
        else if (Array.isArray(rawResult.algos)) algos = rawResult.algos;
    }

    if (sideRaw === null || sideRaw === undefined) return null;
    const s = String(sideRaw)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toUpperCase()
        .trim();

    let normSide = null;
    if (s === "T" || s === "TAI" || s.includes("TAI") || s === "BIG" || s === "OVER" || s === "1") {
        normSide = "T";
    } else if (s === "X" || s === "XIU" || s.includes("XIU") || s === "SMALL" || s === "UNDER" || s === "0" || s === "2") {
        normSide = "X";
    }
    if (!normSide) return null;

    let conf = Number(confRaw);
    if (!Number.isFinite(conf) || conf <= 0) {
        conf = 72;
    } else if (conf <= 1) {
        conf = Math.round(conf * 100);
    } else {
        conf = Math.round(conf);
    }
    conf = clamp(conf, 51, 99);

    let tPct = Number(taiPct);
    let xPct = Number(xiuPct);
    if (!Number.isFinite(tPct) || !Number.isFinite(xPct)) {
        tPct = normSide === "T" ? conf : (100 - conf);
        xPct = 100 - tPct;
    } else {
        tPct = clamp(Math.round(tPct), 1, 99);
        xPct = 100 - tPct;
    }

    const labelSide = normSide === "T" ? "TÀI" : "XỈU";
    return {
        prediction: normSide === "T" ? "tai" : "xiu",
        rawPrediction: normSide,
        confidence: conf,
        tai_pct: tPct,
        xiu_pct: xPct,
        prob_t: +(tPct / 100).toFixed(4),
        prob_x: +(xPct / 100).toFixed(4),
        score_t: normSide === "T" ? +(conf / 50).toFixed(2) : 0.85,
        score_x: normSide === "X" ? +(conf / 50).toFixed(2) : 0.85,
        streak: 0,
        pattern: history.slice(-4).map(h => (h.tx === "T" ? "t" : "x")).join(""),
        bridge_name: bridgeName || `Thuật toán tùy chỉnh (${fileName})`,
        is_too_bad: isTooBad,
        advice_status: adviceStatus || `⚡ TOOL TÙY CHỈNH [${fileName}] - ĐỀ XUẤT ${labelSide} (${conf}%)`,
        algos: algos.length ? algos : [`File: ${fileName}`, `Tín hiệu: ${labelSide} (${conf}%)`],
    };
}

class CustomAlgorithmManager {
    constructor() {
        ensureCustomAlgoDir();
        this.active = false;
        this.fileName = null;
        this.ext = null;
        this.savedPath = null;
        this.uploadedAt = null;
        this.fileSize = 0;
        this.jsRunner = null;
        this.lastRunError = null;
        this._restoreFromDisk();
    }

    _restoreFromDisk() {
        try {
            if (!fs.existsSync(CUSTOM_ALGO_META)) return;
            const meta = JSON.parse(fs.readFileSync(CUSTOM_ALGO_META, "utf8"));
            if (!meta || !meta.fileName || !meta.savedPath || !fs.existsSync(meta.savedPath)) return;
            const code = fs.readFileSync(meta.savedPath, "utf8");
            this._activateInternal(meta.fileName, meta.ext, meta.savedPath, code, meta.uploadedAt, false);
        } catch (err) {
            this.lastRunError = "Lỗi khôi phục file thuật toán đã lưu: " + err.message;
        }
    }

    _buildJsRunner(code, fileName) {
        const cleanedCode = code
            .replace(/^#!.*$/gm, "")
            .replace(/\bsetInterval\s*\(/g, "void(")
            .replace(/\bprocess\.exit\s*\(/g, "void(");

        const sandbox = {
            module: { exports: {} },
            exports: {},
            console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {} },
            Math,
            Date,
            JSON,
            Array,
            Object,
            String,
            Number,
            Boolean,
            RegExp,
            Map,
            Set,
            Promise,
            parseInt,
            parseFloat,
            isNaN,
            isFinite,
            Buffer,
            setTimeout: () => 0,
            clearTimeout: () => {},
            setInterval: () => 0,
            clearInterval: () => {},
            require: (modName) => {
                const allowed = ["crypto", "node:crypto", "util", "node:util", "path", "node:path"];
                if (allowed.includes(modName)) return require(modName);
                return {};
            },
        };
        sandbox.global = sandbox;
        sandbox.globalThis = sandbox;
        sandbox.window = sandbox;
        sandbox.self = sandbox;

        const wrappedScript = `
            ${cleanedCode}
            ;globalThis.__CAPTURED_EXPORTS__ = module.exports;
            globalThis.__CAPTURED_FNS__ = {
                predict: typeof predict === "function" ? predict : null,
                analyze: typeof analyze === "function" ? analyze : null,
                phanTich: typeof phanTich === "function" ? phanTich : null,
                duDoan: typeof duDoan === "function" ? duDoan : null,
                predictTaiXiu: typeof predictTaiXiu === "function" ? predictTaiXiu : null,
                predictTaiXiuClassic: typeof predictTaiXiuClassic === "function" ? predictTaiXiuClassic : null,
                runTool: typeof runTool === "function" ? runTool : null,
                main: typeof main === "function" ? main : null,
            };
        `;

        const ctx = vm.createContext(sandbox);
        const script = new vm.Script(wrappedScript, { filename: fileName });
        script.runInContext(ctx, { timeout: 2500 });

        const exp = sandbox.__CAPTURED_EXPORTS__;
        const fns = sandbox.__CAPTURED_FNS__ || {};

        let targetFn = null;
        let targetInstance = null;

        const fnNames = ["predict", "analyze", "phanTich", "duDoan", "predictTaiXiu", "predictTaiXiuClassic", "runTool", "solve", "forecast", "main"];

        if (typeof exp === "function") {
            if (exp.prototype && typeof exp.prototype.predict === "function") {
                targetInstance = new exp();
                targetFn = targetInstance.predict.bind(targetInstance);
            } else {
                targetFn = exp;
            }
        } else if (exp && typeof exp === "object") {
            for (const key of fnNames) {
                if (typeof exp[key] === "function") {
                    targetFn = exp[key].bind(exp);
                    break;
                }
            }
            if (!targetFn) {
                for (const val of Object.values(exp)) {
                    if (typeof val === "function" && val.prototype && typeof val.prototype.predict === "function") {
                        targetInstance = new val();
                        targetFn = targetInstance.predict.bind(targetInstance);
                        break;
                    }
                    if (typeof val === "function") {
                        targetFn = val;
                        break;
                    }
                }
            }
        }

        if (!targetFn) {
            for (const key of fnNames) {
                if (typeof fns[key] === "function") {
                    targetFn = fns[key];
                    break;
                }
            }
        }

        if (!targetFn) {
            throw new Error("Không tìm thấy hàm dự đoán hợp lệ trong file JS (cần hàm predict / analyze / duDoan / phanTich / module.exports).");
        }

        return (payload) => {
            try {
                const res = targetFn(payload.history, payload);
                if (res !== undefined && res !== null) return res;
            } catch (_) {}
            return targetFn(payload);
        };
    }

    _buildPyHarnessPath() {
        const harnessPath = path.join(CUSTOM_ALGO_DIR, "_py_runner_bridge.py");
        const harnessCode = `import sys, json, inspect, importlib.util

def load_module(py_path):
    spec = importlib.util.spec_from_file_location("user_custom_algo", py_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main():
    raw_in = sys.stdin.read()
    payload = json.loads(raw_in)
    py_path = payload.get("_py_path")
    history = payload.get("history", [])
    mod = load_module(py_path)

    candidate_names = [
        "predict", "analyze", "phan_tich", "phanTich",
        "du_doan", "duDoan", "predict_tai_xiu", "solve", "forecast", "run"
    ]
    fn = None
    for name in candidate_names:
        obj = getattr(mod, name, None)
        if callable(obj):
            fn = obj
            break

    if fn is None:
        for attr_name in dir(mod):
            if attr_name.startswith("_"):
                continue
            obj = getattr(mod, attr_name)
            if inspect.isclass(obj) and hasattr(obj, "predict"):
                inst = obj()
                fn = inst.predict
                break

    if fn is None:
        raise RuntimeError("Không tìm thấy hàm predict / analyze / du_doan / phan_tich trong file Python.")

    sig = inspect.signature(fn)
    params = [p for p in sig.parameters.values() if p.default is inspect.Parameter.empty]
    if len(params) >= 2:
        res = fn(history, payload)
    elif len(params) == 1:
        res = fn(history)
    else:
        res = fn()

    print(json.dumps({"ok": True, "result": res}, ensure_ascii=False))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        sys.exit(1)
`;
        fs.writeFileSync(harnessPath, harnessCode, "utf8");
        return harnessPath;
    }

    _activateInternal(fileName, ext, savedPath, code, uploadedAt, persistMeta = true) {
        let jsRunner = null;
        if (ext === ".js") {
            jsRunner = this._buildJsRunner(code, fileName);
        } else if (ext === ".py") {
            if (!PYTHON_BIN) {
                throw new Error("Môi trường server hiện chưa cài Python (python3/python). Hãy dùng file .js hoặc cài Python trên server.");
            }
            this._buildPyHarnessPath();
        } else {
            throw new Error("Chỉ chấp nhận tệp định dạng .py hoặc .js");
        }

        this.active = true;
        this.fileName = fileName;
        this.ext = ext;
        this.savedPath = savedPath;
        this.uploadedAt = uploadedAt || new Date().toISOString();
        this.fileSize = Buffer.byteLength(code, "utf8");
        this.jsRunner = jsRunner;
        this.lastRunError = null;

        if (persistMeta) {
            ensureCustomAlgoDir();
            fs.writeFileSync(
                CUSTOM_ALGO_META,
                JSON.stringify(
                    {
                        fileName: this.fileName,
                        ext: this.ext,
                        savedPath: this.savedPath,
                        uploadedAt: this.uploadedAt,
                    },
                    null,
                    2
                ),
                "utf8"
            );
        }
    }

    uploadAlgorithm(rawFileName, codeContent) {
        const safeBase = path.basename(String(rawFileName || "").trim());
        const ext = path.extname(safeBase).toLowerCase();
        if (ext !== ".py" && ext !== ".js") {
            throw new Error("Định dạng không hợp lệ! Hệ thống chỉ nhận tệp .py và .js");
        }
        const content = String(codeContent || "");
        if (!content.trim()) {
            throw new Error("Nội dung tệp thuật toán đang trống.");
        }
        if (Buffer.byteLength(content, "utf8") > MAX_ALGO_FILE_BYTES) {
            throw new Error("Dung lượng tệp vượt quá giới hạn 1MB.");
        }

        ensureCustomAlgoDir();
        this._cleanupFilesOnly();

        const savedPath = path.join(CUSTOM_ALGO_DIR, "user_algorithm" + ext);
        fs.writeFileSync(savedPath, content, "utf8");
        this._activateInternal(safeBase, ext, savedPath, content, new Date().toISOString(), true);
        return this.getStatus();
    }

    _cleanupFilesOnly() {
        try {
            if (fs.existsSync(CUSTOM_ALGO_META)) fs.unlinkSync(CUSTOM_ALGO_META);
            for (const f of ["user_algorithm.js", "user_algorithm.py"]) {
                const p = path.join(CUSTOM_ALGO_DIR, f);
                if (fs.existsSync(p)) fs.unlinkSync(p);
            }
        } catch (_) {}
    }

    removeAndRestoreOriginal() {
        this._cleanupFilesOnly();
        this.active = false;
        this.fileName = null;
        this.ext = null;
        this.savedPath = null;
        this.uploadedAt = null;
        this.fileSize = 0;
        this.jsRunner = null;
        this.lastRunError = null;
        return this.getStatus();
    }

    predictWithCustom(history, rawList, channelKey, nextSession) {
        if (!this.active) return null;
        const payload = {
            mode: channelKey,
            phien_tiep_theo: nextSession,
            next_session: nextSession,
            history: history.map(h => ({
                session: h.session,
                phien: h.session,
                tx: h.tx,
                ket_qua: h.tx === "T" ? "TÀI" : "XỈU",
                dice: h.dice,
                xuc_xac: h.dice,
                total: h.total,
                tong_diem: h.total,
            })),
            list: rawList,
        };

        try {
            let rawOut = null;
            if (this.ext === ".js" && this.jsRunner) {
                rawOut = this.jsRunner(payload);
            } else if (this.ext === ".py" && this.savedPath && PYTHON_BIN) {
                const harnessPath = path.join(CUSTOM_ALGO_DIR, "_py_runner_bridge.py");
                if (!fs.existsSync(harnessPath)) this._buildPyHarnessPath();
                const pyPayload = JSON.stringify({ ...payload, _py_path: this.savedPath });
                const execRes = spawnSync(PYTHON_BIN, [harnessPath], {
                    input: pyPayload,
                    encoding: "utf8",
                    timeout: 4500,
                    maxBuffer: 1024 * 1024,
                });
                if (execRes.status !== 0) {
                    const errMsg = (execRes.stderr || execRes.stdout || "Lỗi thực thi Python").trim();
                    throw new Error(errMsg.slice(0, 260));
                }
                const outLines = (execRes.stdout || "").trim().split(/\r?\n/);
                const lastLine = outLines[outLines.length - 1] || "{}";
                const parsed = JSON.parse(lastLine);
                if (!parsed.ok) {
                    throw new Error(parsed.error || "Python trả về lỗi");
                }
                rawOut = parsed.result;
            }

            const normalized = normalizeExternalPrediction(rawOut, history, this.fileName);
            if (!normalized) {
                throw new Error("File thuật toán không trả về kết quả TÀI/XỈU hợp lệ.");
            }
            this.lastRunError = null;
            return normalized;
        } catch (err) {
            this.lastRunError = err.message;
            const last = history[history.length - 1];
            const fallbackSide = last && last.tx === "T" ? "X" : "T";
            return {
                prediction: fallbackSide === "T" ? "tai" : "xiu",
                rawPrediction: fallbackSide,
                confidence: 52,
                tai_pct: fallbackSide === "T" ? 52 : 48,
                xiu_pct: fallbackSide === "X" ? 52 : 48,
                prob_t: fallbackSide === "T" ? 0.52 : 0.48,
                prob_x: fallbackSide === "X" ? 0.52 : 0.48,
                score_t: 1,
                score_x: 1,
                streak: 0,
                pattern: "",
                bridge_name: `Lỗi chạy tool (${this.fileName})`,
                is_too_bad: true,
                advice_status: `⚠️ LỖI FILE TOOL: ${err.message}`,
                algos: [`File: ${this.fileName}`, "Trạng thái: Lỗi thực thi"],
            };
        }
    }

    getStatus() {
        return {
            active: this.active,
            engine_mode: this.active ? "CUSTOM_TOOL" : "ORIGINAL_SUPER_HYBRID_V3",
            engine_label: this.active
                ? `Tool Tùy Chỉnh (${this.fileName})`
                : "SuperHybridAIEngine v3.0 (Thuật Toán Gốc)",
            file_name: this.fileName,
            file_ext: this.ext,
            file_size: this.fileSize,
            uploaded_at: this.uploadedAt,
            python_supported: Boolean(PYTHON_BIN),
            last_error: this.lastRunError,
        };
    }
}

const customAlgoManager = new CustomAlgorithmManager();


// ============================================================================

// ============================================================================
// CẤU HÌNH BẢO MẬT ADMIN, KHÓA/MỞ API & MÃ HÓA NHẬT KÝ MẠNG
// ============================================================================
const ADMIN_USER = "vkhanh";
const ADMIN_PASS = "2011";
const SERVER_SECRET_KEY = crypto.createHash("sha256").update("LC79_VIP_vkhanh_2011_NET_SHIELD").digest();
const activeSessions = new Map(); // token -> { user, expiresAt, netKeyHex }
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const API_LOCK_FILE = path.join(CUSTOM_ALGO_DIR, "api_locks.json");

class ApiLockManager {
    constructor() {
        ensureCustomAlgoDir();
        this.locks = {
            md5: false,
            tx: false,
            raw_md5: false,
            raw_tx: false,
            all: false,
        };
        this._load();
    }

    _load() {
        try {
            if (fs.existsSync(API_LOCK_FILE)) {
                const parsed = JSON.parse(fs.readFileSync(API_LOCK_FILE, "utf8"));
                if (parsed && typeof parsed === "object") {
                    this.locks = { ...this.locks, ...parsed };
                }
            }
        } catch (_) {}
    }

    _save() {
        try {
            ensureCustomAlgoDir();
            fs.writeFileSync(API_LOCK_FILE, JSON.stringify(this.locks, null, 2), "utf8");
        } catch (_) {}
    }

    isLocked(key) {
        return Boolean(this.locks[key]);
    }

    setLock(key, locked) {
        if (key === "ALL_APIS") {
            const val = Boolean(locked);
            for (const k of Object.keys(this.locks)) {
                this.locks[k] = val;
            }
            this._save();
            return this.getStatus();
        }
        if (Object.prototype.hasOwnProperty.call(this.locks, key)) {
            this.locks[key] = Boolean(locked);
            this._save();
        }
        return this.getStatus();
    }

    getStatus() {
        return { ...this.locks };
    }
}

const apiLockManager = new ApiLockManager();

function parseCookies(req) {
    const raw = req.headers.cookie || "";
    const out = {};
    raw.split(";").forEach(part => {
        const idx = part.indexOf("=");
        if (idx > 0) {
            const k = part.slice(0, idx).trim();
            const v = part.slice(idx + 1).trim();
            out[k] = decodeURIComponent(v);
        }
    });
    return out;
}

function getAuthSession(req) {
    const cookies = parseCookies(req);
    const token = cookies.lc79_admin_sid || req.headers["x-admin-token"];
    if (!token) return null;
    const sess = activeSessions.get(token);
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) {
        activeSessions.delete(token);
        return null;
    }
    return { token, ...sess };
}

function createAuthSession(user) {
    const token = crypto.randomBytes(24).toString("hex");
    const netKeyHex = crypto.randomBytes(32).toString("hex");
    const sess = {
        user,
        netKeyHex,
        expiresAt: Date.now() + SESSION_TTL_MS,
    };
    activeSessions.set(token, sess);
    return { token, ...sess };
}

// Mã hóa AES-256-GCM cho Nhật ký mạng (Network Traffic Encryption)
function encryptNetworkPacket(payloadObj, keyHex) {
    const keyBuf = Buffer.from(keyHex, "hex");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, iv);
    const plain = Buffer.from(JSON.stringify(payloadObj), "utf8");
    const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        _enc: 1,
        v: "LC79-NET-AES256",
        ts: Date.now(),
        iv: iv.toString("base64"),
        tag: tag.toString("base64"),
        d: enc.toString("base64"),
    };
}

function decryptNetworkPacket(packet, keyHex) {
    if (!packet || packet._enc !== 1) return packet;
    const keyBuf = Buffer.from(keyHex, "hex");
    const iv = Buffer.from(packet.iv, "base64");
    const tag = Buffer.from(packet.tag, "base64");
    const data = Buffer.from(packet.d, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    return JSON.parse(dec.toString("utf8"));
}

// Mã hóa mã nguồn HTML/JS trả về trình duyệt chống View-Source / Crack
function obfuscateHtmlResponse(rawHtml) {
    const compressed = zlib.deflateRawSync(Buffer.from(rawHtml, "utf8"));
    const xorKey = crypto.randomBytes(16);
    const masked = Buffer.alloc(compressed.length);
    for (let i = 0; i < compressed.length; i++) {
        masked[i] = compressed[i] ^ xorKey[i % xorKey.length];
    }
    const b64Payload = masked.toString("base64");
    const b64Key = xorKey.toString("base64");

    return `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>LC79 VIP SHIELD • PROTECTED</title>
<style>html,body{background:#090b10;color:#94a3b8;font-family:monospace;margin:0;padding:0;}</style>
</head>
<body>
<noscript>Vui lòng bật JavaScript để truy cập hệ thống.</noscript>
<script>
(async function(){
  try{
    var _0x9a1="${b64Payload}";
    var _0x4k2="${b64Key}";
    var _b1=Uint8Array.from(atob(_0x9a1),function(c){return c.charCodeAt(0);});
    var _k1=Uint8Array.from(atob(_0x4k2),function(c){return c.charCodeAt(0);});
    var _out=new Uint8Array(_b1.length);
    for(var i=0;i<_b1.length;i++){_out[i]=_b1[i]^_k1[i%_k1.length];}
    var ds=new DecompressionStream("deflate-raw");
    var writer=ds.writable.getWriter();
    writer.write(_out);
    writer.close();
    var resp=new Response(ds.readable);
    var html=await resp.text();
    document.open();
    document.write(html);
    document.close();
  }catch(e){
    document.body.innerHTML="<div style='padding:24px;color:#fb7185;'>Trình duyệt không hỗ trợ giải mã bảo mật.</div>";
  }
})();
</script>
</body>
</html>`;
}

// ============================================================================
// BỘ ĐIỀU PHỐI PHÂN TÍCH REALTIME & THỐNG KÊ THẮNG / THUA / CHUỖI MAX
// ============================================================================
function normalizeApiPayload(data) {
    return Array.isArray(data)
        ? { list: data }
        : (data && Array.isArray(data.list)
            ? data
            : (data && data.data && Array.isArray(data.data.list) ? data.data : data));
}

class ChannelAnalyzer {
    constructor(channelKey, gameLabel, endpoints) {
        this.channelKey = channelKey;
        this.gameLabel = gameLabel;
        this.endpoints = endpoints;
        this.engine = new SuperHybridAIEngine();

        this.txHistory = [];
        this.rawList = [];
        this.rawUpstreamPayload = null;
        this.currentSessionId = null;
        this.lastPredictedSession = null;
        this.lastPredictedSide = null;
        this.lastPredictedConf = null;
        this.lastPredictedBridge = null;
        this.prediction = null;
        this.nextSession = null;

        this.totalAnalyzed = 0;
        this.wins = 0;
        this.losses = 0;
        this.curWinStreak = 0;
        this.curLossStreak = 0;
        this.maxWinStreak = 0;
        this.maxLossStreak = 0;

        this.historyLog = [];
        this.isFetching = false;
        this.lastUpdatedAt = null;
        this.lastError = null;
        this.activeEndpoint = null;
    }

    runPredictionForCurrentHistory(nextSession) {
        if (customAlgoManager.active) {
            return customAlgoManager.predictWithCustom(
                this.txHistory,
                this.rawList,
                this.channelKey,
                nextSession
            );
        }
        return this.engine.predict(this.txHistory);
    }

    recomputeCurrentPrediction() {
        if (!this.txHistory.length) return;
        const nextSession = (this.currentSessionId || this.txHistory[this.txHistory.length - 1].session) + 1;
        const prediction = this.runPredictionForCurrentHistory(nextSession);
        this.prediction = prediction;
        this.nextSession = nextSession;
        this.lastPredictedSession = nextSession;
        this.lastPredictedSide = prediction.rawPrediction;
        this.lastPredictedConf = prediction.confidence;
        this.lastPredictedBridge = prediction.bridge_name;
    }

    async fetchAndAnalyze() {
        if (this.isFetching) return false;
        this.isFetching = true;
        try {
            let parsed = null;
            let rawItems = null;
            let rawData = null;
            let usedEndpoint = null;

            for (const url of this.endpoints) {
                try {
                    const data = await httpRequestJson(url, { headers: DEFAULT_HEADERS, timeout: 10000 });
                    const normalized = normalizeApiPayload(data);
                    const rows = parseLines(normalized);
                    if (rows.length > 0) {
                        parsed = rows;
                        rawData = data;
                        rawItems = Array.isArray(normalized.list) ? normalized.list : [];
                        usedEndpoint = url;
                        break;
                    }
                } catch (e) {
                    // Thử nguồn dự phòng tiếp theo
                }
            }

            if (!parsed || parsed.length === 0) {
                this.lastError = "Không thể kết nối tới API nguồn";
                return false;
            }

            this.lastError = null;
            this.activeEndpoint = usedEndpoint;
            this.lastUpdatedAt = new Date().toISOString();
            this.rawUpstreamPayload = rawData;

            const prevSessionId = this.currentSessionId;
            this.txHistory = parsed;
            this.currentSessionId = parsed[parsed.length - 1].session;

            this.rawList = [...parsed]
                .sort((a, b) => b.session - a.session)
                .slice(0, 100)
                .map(item => {
                    const orig = rawItems.find(r => Number(r.id) === item.session);
                    return {
                        id: item.session,
                        ...(orig && orig._id ? { _id: orig._id } : {}),
                        resultTruyenThong: item.tx === "T" ? "TAI" : "XIU",
                        dices: item.dice,
                        point: item.total,
                    };
                });

            if (this.currentSessionId !== prevSessionId) {
                if (this.lastPredictedSession !== null && this.lastPredictedSide !== null) {
                    const matched = this.txHistory.find(item => item.session === this.lastPredictedSession);
                    if (matched) {
                        const won = matched.tx === this.lastPredictedSide;
                        if (!customAlgoManager.active) {
                            this.engine.updateActual(matched.tx, this.lastPredictedSide);
                        }
                        this.totalAnalyzed++;
                        if (won) {
                            this.wins++;
                            this.curWinStreak++;
                            this.curLossStreak = 0;
                            if (this.curWinStreak > this.maxWinStreak) this.maxWinStreak = this.curWinStreak;
                        } else {
                            this.losses++;
                            this.curLossStreak++;
                            this.curWinStreak = 0;
                            if (this.curLossStreak > this.maxLossStreak) this.maxLossStreak = this.curLossStreak;
                        }
                        this.historyLog.unshift({
                            phien: matched.session,
                            du_doan: this.lastPredictedSide === "T" ? "TÀI" : "XỈU",
                            rawPrediction: this.lastPredictedSide,
                            do_tin_cay: this.lastPredictedConf,
                            cau: this.lastPredictedBridge || "Đang dò cầu",
                            ket_qua: matched.tx === "T" ? "TÀI" : "XỈU",
                            rawResult: matched.tx,
                            xuc_xac: matched.dice,
                            tong_diem: matched.total,
                            trang_thai: won ? "THẮNG" : "THUA",
                            won,
                            thoi_gian: new Date().toISOString(),
                        });
                        if (this.historyLog.length > 100) this.historyLog.pop();
                    } else if (!customAlgoManager.active) {
                        const latest = this.txHistory[this.txHistory.length - 1];
                        this.engine.updateActual(latest.tx, null);
                    }
                }

                this.recomputeCurrentPrediction();
            }

            return true;
        } finally {
            this.isFetching = false;
        }
    }

    // API gốc chưa phân tích (dữ liệu phiên gốc nguyên bản)
    toRawApiResponse() {
        const latest = this.txHistory.length ? this.txHistory[this.txHistory.length - 1] : null;
        return {
            status: this.txHistory.length ? "ok" : "initializing",
            type: "RAW_UNANALYZED_ORIGIN_API",
            game: this.gameLabel,
            mode: this.channelKey,
            updated_at: this.lastUpdatedAt,
            phien_hien_tai: this.currentSessionId,
            phien_tiep_theo: this.currentSessionId ? this.currentSessionId + 1 : null,
            ket_qua_vua_ve: latest
                ? {
                    phien: latest.session,
                    xuc_xac: latest.dice,
                    tong_diem: latest.total,
                    ket_qua: latest.tx === "T" ? "TÀI" : "XỈU",
                    tx: latest.tx,
                }
                : null,
            total: this.rawList.length,
            list: this.rawList,
            raw_source: this.rawUpstreamPayload,
            ...(this.lastError ? { error: this.lastError } : {}),
        };
    }

    // API phân tích chuẩn JSON theo mẫu ảnh (vẫn giữ đầy đủ các trường gốc cho tool)
    toApiResponse() {
        const p = this.prediction;
        const latest = this.txHistory.length ? this.txHistory[this.txHistory.length - 1] : null;
        const winRateNum = this.totalAnalyzed > 0
            ? Number(((this.wins / this.totalAnalyzed) * 100).toFixed(1))
            : 0;
        const winLossSummary = `${this.wins} Thắng / ${this.losses} Thua`;
        const maxStreakSummary = `Thắng max: ${this.maxWinStreak} | Thua max: ${this.maxLossStreak}`;
        const algoStatus = customAlgoManager.getStatus();

        // Tính chuỗi hiện tại có dấu (+win / -loss) theo mẫu ảnh
        const signedStreak = this.curWinStreak > 0
            ? this.curWinStreak
            : (this.curLossStreak > 0 ? -this.curLossStreak : 0);

        const last20 = this.historyLog.slice(0, 20);
        const last50 = this.historyLog.slice(0, 50);
        const win20 = last20.length ? ((last20.filter(x => x.won).length / last20.length) * 100).toFixed(1) + "%" : "0.0%";
        const win50 = last50.length ? ((last50.filter(x => x.won).length / last50.length) * 100).toFixed(1) + "%" : "0.0%";

        const taiLogs = this.historyLog.filter(x => x.rawPrediction === "T");
        const taiWins = taiLogs.filter(x => x.won).length;
        const taiEff = taiLogs.length ? `${taiWins}/${taiLogs.length} (${((taiWins / taiLogs.length) * 100).toFixed(2)}%)` : "0/0 (0.00%)";

        const xiuLogs = this.historyLog.filter(x => x.rawPrediction === "X");
        const xiuWins = xiuLogs.filter(x => x.won).length;
        const xiuEff = xiuLogs.length ? `${xiuWins}/${xiuLogs.length} (${((xiuWins / xiuLogs.length) * 100).toFixed(2)}%)` : "0/0 (0.00%)";

        // Xây dựng mảng data từng phiên theo đúng format ảnh mẫu
        const dataItems = [];
        if (this.nextSession && p) {
            const predTitle = p.rawPrediction === "T" ? "Tai" : "Xiu";
            dataItems.push({
                phien: String(this.nextSession),
                du_doan: predTitle,
                du_doan_nhan: predTitle,
                ti_le: `${Number(p.confidence || 0).toFixed(2)}%`,
                ket_qua: "Dang cho",
                ket_qua_nhan: "Dang cho",
                danh_gia: "Chờ kết quả",
                danh_gia_thuc_te: "⏳ Chờ kết quả",
                is_correct: null,
            });
        }
        for (const item of this.historyLog) {
            const predTitle = item.rawPrediction === "T" ? "Tai" : "Xiu";
            const resTitle = item.rawResult === "T" ? "Tai" : "Xiu";
            dataItems.push({
                phien: String(item.phien),
                du_doan: predTitle,
                du_doan_nhan: predTitle,
                ti_le: `${Number(item.do_tin_cay || 0).toFixed(2)}%`,
                ket_qua: resTitle,
                ket_qua_nhan: resTitle,
                danh_gia: item.won ? "Đúng" : "Sai",
                danh_gia_thuc_te: item.won ? "✅ Thắng thực tế" : `❌ Sai (${item.cau || "Đã hiệu chuẩn"})`,
                is_correct: Boolean(item.won),
            });
        }

        return {
            id: "@vkhanh3010",
            version: "V4",
            type: `${this.gameLabel} - Lịch sử dự đoán AI`,
            status: p ? "ok" : "initializing",
            game: this.gameLabel,
            mode: this.channelKey,
            updated_at: this.lastUpdatedAt,

            // Thống kê theo mẫu ảnh + thống kê chi tiết
            thong_ke: {
                tong_da_du_doan: this.totalAnalyzed,
                so_tran_dung: this.wins,
                so_tran_sai: this.losses,
                win_rate_that: `${winRateNum.toFixed(2)}%`,
                win_rate_20_gan_nhat: win20,
                win_rate_50_gan_nhat: win50,
                chuoi_hien_tai: signedStreak,
                chuoi_thang_max: this.maxWinStreak,
                chuoi_thua_max: this.maxLossStreak,
                hieu_suat_tai: taiEff,
                hieu_suat_xiu: xiuEff,
                ket_qua_nhan: "Dang cho",
                danh_gia_ket_qua: "⏳ Chờ kết quả",
                phien_hien_tai_dang_du_doan: this.nextSession,
                tong_phan_tich: this.totalAnalyzed,
                tong_thang: this.wins,
                tong_thua: this.losses,
                tong_thang_thua: winLossSummary,
                ty_le_thang: `${winRateNum.toFixed(1)}%`,
                chuoi_thang_cao_nhat: this.maxWinStreak,
                chuoi_thua_cao_nhat: this.maxLossStreak,
                chuoi_thang_thua_cao_nhat: maxStreakSummary,
                chuoi_thang_hien_tai: this.curWinStreak,
                chuoi_thua_hien_tai: this.curLossStreak,
            },
            total: dataItems.length,
            data: dataItems,

            // Trạng thái bộ thuật toán đang chạy (Gốc hoặc Tool mới .py/.js)
            thuat_toan_dang_chay: algoStatus,

            // Thông tin phiên hiện tại đang dự đoán & phiên vừa chốt
            phien_hien_tai_dang_du_doan: this.nextSession,
            phien_du_doan: this.nextSession,
            phien_vua_chot: this.currentSessionId,
            phien_hien_tai: this.currentSessionId,

            // Kết quả phân tích dự đoán cho phiên hiện tại đang chạy
            du_doan: p ? (p.rawPrediction === "T" ? "TÀI" : "XỈU") : null,
            prediction: p ? p.prediction : null,
            rawPrediction: p ? p.rawPrediction : null,
            do_tin_cay: p ? p.confidence : null,
            confidence: p ? p.confidence : null,
            ty_le_tai: p ? p.tai_pct : null,
            ty_le_xiu: p ? p.xiu_pct : null,
            cau: p ? p.bridge_name : null,
            cau_xau: p ? p.is_too_bad : null,
            khuyen_nghi: p ? p.advice_status : null,
            thuat_toan: p ? p.algos : [],

            // Tổng Thắng / Thua & Chuỗi Thắng / Thua cao nhất
            tong_phan_tich: this.totalAnalyzed,
            tong_thang: this.wins,
            tong_thua: this.losses,
            tong_thang_thua: winLossSummary,
            ty_le_thang: `${winRateNum.toFixed(1)}%`,
            chuoi_thang_cao_nhat: this.maxWinStreak,
            chuoi_thua_cao_nhat: this.maxLossStreak,
            chuoi_thang_thua_cao_nhat: maxStreakSummary,
            chuoi_thang_hien_tai: this.curWinStreak,
            chuoi_thua_hien_tai: this.curLossStreak,

            ket_qua_vua_ve: latest
                ? {
                    phien: latest.session,
                    xuc_xac: latest.dice,
                    tong_diem: latest.total,
                    ket_qua: latest.tx === "T" ? "TÀI" : "XỈU",
                    tx: latest.tx,
                }
                : null,

            // Lịch sử phân tích & đối soát từng phiên
            lich_su_doi_soat: this.historyLog.slice(0, 25),
            list: this.rawList.slice(0, 20),
            ...(this.lastError ? { error: this.lastError } : {}),
        };
    }
}

const analyzers = {
    tx: new ChannelAnalyzer("tx", "LC79 • TXHU", TX_TOOL_ENDPOINTS),
    md5: new ChannelAnalyzer("md5", "LC79 • TXMD5", MD5_TOOL_ENDPOINTS),
};

async function pollAllChannels() {
    await Promise.allSettled([
        analyzers.tx.fetchAndAnalyze(),
        analyzers.md5.fetchAndAnalyze(),
    ]);
}

function recomputeAllChannelsNow() {
    analyzers.tx.recomputeCurrentPrediction();
    analyzers.md5.recomputeCurrentPrediction();
}

function readJsonBody(req, maxBytes = 1500000) {
    return new Promise((resolve, reject) => {
        let total = 0;
        const chunks = [];
        req.on("data", chunk => {
            total += chunk.length;
            if (total > maxBytes) {
                req.destroy();
                reject(new Error("Dữ liệu tải lên vượt quá dung lượng cho phép."));
                return;
            }
            chunks.push(chunk);
        });
        req.on("end", () => {
            try {
                const raw = Buffer.concat(chunks).toString("utf8");
                resolve(raw ? JSON.parse(raw) : {});
            } catch (e) {
                reject(new Error("Định dạng dữ liệu JSON không hợp lệ."));
            }
        });
        req.on("error", reject);
    });
}

function sendJson(res, statusCode, payload, pretty = true) {
    const body = pretty ? JSON.stringify(payload, null, 2) : JSON.stringify(payload);
    res.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Token, X-Net-Encrypted",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    });
    res.end(body);
}

// ============================================================================
// GIAO DIỆN ĐĂNG NHẬP ADMIN (vkhanh / 2011)
// ============================================================================
function renderLoginHtml() {
    return `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>ĐĂNG NHẬP QUẢN TRỊ • LC79 VIP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, sans-serif;
    background: radial-gradient(circle at 20% 10%, rgba(245, 158, 11, 0.14), transparent 40%), #090b10;
    color: #f8fafc;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
  }
  .login-card {
    width: 100%;
    max-width: 390px;
    background: rgba(17, 21, 31, 0.94);
    border: 1px solid rgba(245, 197, 66, 0.36);
    border-radius: 16px;
    padding: 24px 22px;
    box-shadow: 0 18px 42px rgba(0,0,0,0.55);
  }
  .badge {
    display: inline-block;
    font-size: 11px;
    font-weight: 800;
    padding: 4px 10px;
    border-radius: 999px;
    background: rgba(245, 158, 11, 0.15);
    color: #fde047;
    border: 1px solid rgba(245, 158, 11, 0.35);
    margin-bottom: 10px;
  }
  h1 {
    font-size: 18px;
    font-weight: 900;
    margin-bottom: 6px;
    color: #ffffff;
  }
  p {
    font-size: 12.5px;
    color: #94a3b8;
    margin-bottom: 18px;
    line-height: 1.45;
  }
  .field { margin-bottom: 13px; }
  label {
    display: block;
    font-size: 11.5px;
    font-weight: 700;
    color: #cbd5e1;
    margin-bottom: 6px;
  }
  input {
    width: 100%;
    padding: 11px 12px;
    border-radius: 10px;
    border: 1px solid rgba(255,255,255,0.14);
    background: #0b0e16;
    color: #f8fafc;
    font-size: 13.5px;
    outline: none;
  }
  input:focus { border-color: #f59e0b; }
  .btn-submit {
    width: 100%;
    padding: 12px;
    border-radius: 10px;
    border: none;
    background: linear-gradient(135deg, #f59e0b, #eab308);
    color: #090b10;
    font-size: 13.5px;
    font-weight: 900;
    cursor: pointer;
    margin-top: 4px;
  }
  .btn-submit:hover { filter: brightness(1.06); }
  .err {
    margin-top: 12px;
    font-size: 12px;
    color: #fda4af;
    background: rgba(244, 63, 94, 0.15);
    border: 1px solid rgba(251, 113, 133, 0.38);
    padding: 9px 11px;
    border-radius: 9px;
    display: none;
  }
  .note {
    margin-top: 14px;
    font-size: 11px;
    color: #64748b;
    text-align: center;
  }
</style>
</head>
<body>
<div class="login-card">
  <div class="badge">🔒 ADMIN SECURITY GATE</div>
  <h1>ĐĂNG NHẬP HỆ THỐNG VIP</h1>
  <p>Vui lòng xác thực tài khoản quản trị để truy cập bảng điều khiển và quản lý khóa/mở API.</p>
  <form id="loginForm">
    <div class="field">
      <label for="u">Tài khoản Admin</label>
      <input type="text" id="u" autocomplete="username" placeholder="Nhập tài khoản..." required />
    </div>
    <div class="field">
      <label for="p">Mật khẩu</label>
      <input type="password" id="p" autocomplete="current-password" placeholder="Nhập mật khẩu..." required />
    </div>
    <button type="submit" class="btn-submit">ĐĂNG NHẬP VÀO WEB</button>
    <div class="err" id="errBox"></div>
  </form>
  <div class="note">Các endpoint API vẫn hoạt động độc lập cho Tool ngoài</div>
</div>
<script>
document.getElementById("loginForm").addEventListener("submit", async function(e) {
  e.preventDefault();
  const errBox = document.getElementById("errBox");
  errBox.style.display = "none";
  const username = document.getElementById("u").value.trim();
  const password = document.getElementById("p").value;
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      errBox.textContent = data.error || "Sai tài khoản hoặc mật khẩu!";
      errBox.style.display = "block";
      return;
    }
    window.location.href = "/";
  } catch (err) {
    errBox.textContent = "Lỗi kết nối máy chủ: " + err.message;
    errBox.style.display = "block";
  }
});
</script>
</body>
</html>`;
}

// ============================================================================
// GIAO DIỆN API PHIÊN GIỐNG ẢNH MẪU 100% (Chrome JSON Viewer + Tạo bản in đẹp)
// ============================================================================
function renderApiSessionPageHtml(channelKey, payloadObj) {
    const rawJsonStr = JSON.stringify(payloadObj);
    const prettyJsonStr = JSON.stringify(payloadObj, null, 2);
    const esc = (s) => String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

    return `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>API Phiên ${channelKey.toUpperCase()} • JSON</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 0;
    background: #ffffff;
    color: #000000;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 12px;
    line-height: 1.4;
  }
  .pretty-bar {
    position: sticky;
    top: 0;
    z-index: 10;
    background: #f1f3f4;
    border-bottom: 1px solid #dadce0;
    padding: 6px 10px;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 12px;
    color: #202124;
    display: flex;
    align-items: center;
    gap: 6px;
    user-select: none;
  }
  .pretty-bar label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
  }
  .pretty-bar input[type="checkbox"] {
    width: 14px;
    height: 14px;
    accent-color: #1a73e8;
    cursor: pointer;
    margin: 0;
  }
  pre#jsonContent {
    margin: 0;
    padding: 8px 10px 24px;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 11.5px;
    line-height: 1.38;
    color: #000000;
  }
  pre#jsonContent.raw-mode {
    white-space: pre-wrap;
    word-break: break-all;
  }
</style>
</head>
<body>
<div class="pretty-bar">
  <label>
    <span>Tạo bản in đẹp</span>
    <input type="checkbox" id="chkPretty" checked />
  </label>
</div>
<pre id="jsonContent">${esc(prettyJsonStr)}</pre>
<script>
  const RAW_DATA = ${rawJsonStr};
  const preEl = document.getElementById("jsonContent");
  const chk = document.getElementById("chkPretty");
  chk.addEventListener("change", function() {
    if (chk.checked) {
      preEl.classList.remove("raw-mode");
      preEl.textContent = JSON.stringify(RAW_DATA, null, 2);
    } else {
      preEl.classList.add("raw-mode");
      preEl.textContent = JSON.stringify(RAW_DATA);
    }
  });
</script>
</body>
</html>`;
}

// ============================================================================
// GIAO DIỆN QUẢN TRỊ VIP (TÍCH HỢP KHÓA/MỞ API, API GỐC, MÃ HÓA NETWORK)
// ============================================================================
function renderDashboardHtml(initialMode = "md5", sessionObj = null) {
    const safeMode = initialMode === "tx" ? "tx" : "md5";
    const netKeyHex = sessionObj ? sessionObj.netKeyHex : "";
    return `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>LC79 VIP AI ANALYZER • PHÂN TÍCH TỪNG PHIÊN & API</title>
<style>
  :root {
    --bg-main: #090b10;
    --bg-card: rgba(17, 21, 31, 0.88);
    --bg-elevated: rgba(24, 30, 44, 0.92);
    --border-subtle: rgba(255, 255, 255, 0.08);
    --border-gold: rgba(245, 197, 66, 0.34);
    --gold-1: #fde047;
    --gold-2: #f59e0b;
    --cyan: #38bdf8;
    --emerald: #34d399;
    --rose: #fb7185;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "Inter", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background:
      radial-gradient(circle at 12% 0%, rgba(245, 158, 11, 0.11), transparent 36%),
      radial-gradient(circle at 88% 8%, rgba(56, 189, 248, 0.11), transparent 38%),
      var(--bg-main);
    color: var(--text-primary);
    min-height: 100vh;
    padding: 16px 14px 36px;
    display: flex;
    justify-content: center;
  }
  .container {
    width: 100%;
    max-width: 860px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .vip-card {
    background: var(--bg-card);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid var(--border-subtle);
    border-radius: 16px;
    padding: 16px 18px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.42);
  }
  .vip-card-gold {
    border-color: var(--border-gold);
    background: linear-gradient(160deg, rgba(24, 28, 40, 0.94), rgba(14, 17, 25, 0.96));
  }

  /* HEADER VIP */
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
  }
  .brand-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .vip-crown {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: linear-gradient(135deg, #f59e0b, #fde047);
    color: #0f172a;
    font-weight: 900;
    font-size: 13px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 16px rgba(245, 158, 11, 0.35);
    letter-spacing: 0.4px;
  }
  .title {
    font-size: 15.5px;
    font-weight: 900;
    letter-spacing: 0.35px;
    background: linear-gradient(90deg, #ffffff 10%, #fde68a 60%, #f59e0b 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .sub-title { font-size: 11.5px; color: var(--text-secondary); margin-top: 2px; }
  .header-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .badge-online {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 800;
    padding: 5px 11px;
    border-radius: 999px;
    background: rgba(16, 185, 129, 0.14);
    color: #34d399;
    border: 1px solid rgba(52, 211, 153, 0.35);
  }
  .pulse-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #34d399;
    box-shadow: 0 0 8px #34d399;
    animation: pulseAnim 1.6s infinite;
  }
  @keyframes pulseAnim {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.45; transform: scale(0.82); }
  }

  /* TABS MD5 / TX */
  .mode-tabs {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  .mode-btn {
    padding: 13px 14px;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(15, 19, 28, 0.92);
    color: #94a3b8;
    font-size: 13.5px;
    font-weight: 800;
    letter-spacing: 0.3px;
    cursor: pointer;
    transition: all 0.18s ease;
  }
  .mode-btn:hover { border-color: rgba(245, 197, 66, 0.35); color: #e2e8f0; }
  .mode-btn.active {
    background: linear-gradient(135deg, rgba(245, 158, 11, 0.18), rgba(56, 189, 248, 0.14));
    color: #ffffff;
    border-color: rgba(251, 191, 36, 0.65);
    box-shadow: 0 4px 20px rgba(245, 158, 11, 0.16);
  }

  /* KHỐI THÔNG TIN & LINK API THIẾT KẾ THEO MẪU VIP */
  .api-vip-showcase {
    background: linear-gradient(155deg, #131824 0%, #0d111a 100%);
    border: 1px solid rgba(245, 197, 66, 0.38);
    border-radius: 16px;
    padding: 16px 18px;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.45);
  }
  .api-showcase-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    padding-bottom: 11px;
    margin-bottom: 12px;
    border-bottom: 1px dashed rgba(255, 255, 255, 0.1);
  }
  .api-showcase-title {
    font-size: 12px;
    font-weight: 900;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    color: #fde047;
    display: flex;
    align-items: center;
    gap: 7px;
  }
  .api-mode-pill {
    font-size: 10.5px;
    font-weight: 800;
    padding: 3px 9px;
    border-radius: 999px;
    background: rgba(56, 189, 248, 0.14);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.32);
  }
  .api-info-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 13px;
  }
  .api-info-row {
    display: flex;
    align-items: center;
    gap: 9px;
    font-size: 12.5px;
    color: #cbd5e1;
    background: rgba(255, 255, 255, 0.025);
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 7px 10px;
    border-radius: 9px;
  }
  .api-info-icon {
    font-size: 13px;
    width: 20px;
    text-align: center;
    flex-shrink: 0;
  }
  .api-info-label {
    color: #94a3b8;
    font-weight: 600;
    min-width: 118px;
  }
  .api-info-val {
    color: #f8fafc;
    font-weight: 700;
    word-break: break-all;
  }
  .api-url-box {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    background: #07090d;
    border: 1px solid rgba(56, 189, 248, 0.32);
    border-radius: 11px;
    padding: 6px 8px 6px 12px;
    margin-bottom: 10px;
  }
  .api-input {
    flex: 1;
    min-width: 200px;
    background: transparent;
    border: none;
    color: #38bdf8;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12.5px;
    font-weight: 700;
    outline: none;
  }
  .btn {
    padding: 8px 13px;
    border-radius: 9px;
    border: 1px solid rgba(255, 255, 255, 0.14);
    background: #1e2433;
    color: #f8fafc;
    font-size: 12px;
    font-weight: 800;
    cursor: pointer;
    text-decoration: none;
    white-space: nowrap;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .btn:hover { background: #293246; border-color: rgba(255, 255, 255, 0.25); }
  .btn-gold {
    background: linear-gradient(135deg, #f59e0b, #eab308);
    border-color: #fde047;
    color: #090b10;
  }
  .btn-gold:hover { filter: brightness(1.07); }
  .btn-danger {
    background: rgba(225, 29, 72, 0.18);
    border-color: rgba(251, 113, 133, 0.45);
    color: #fda4af;
  }
  .btn-danger:hover { background: rgba(225, 29, 72, 0.3); color: #fff; }
  .btn-emerald {
    background: rgba(16, 185, 129, 0.18);
    border-color: rgba(52, 211, 153, 0.45);
    color: #6ee7b7;
  }
  .btn-emerald:hover { background: rgba(16, 185, 129, 0.3); color: #fff; }

  /* KHÓA / MỞ API GRID */
  .lock-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 9px;
    margin-top: 8px;
  }
  @media (max-width: 640px) {
    .lock-grid { grid-template-columns: 1fr; }
  }
  .lock-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    background: rgba(9, 12, 18, 0.88);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    padding: 9px 12px;
  }
  .lock-name {
    font-size: 12.5px;
    font-weight: 800;
    color: #f8fafc;
  }
  .lock-path {
    font-size: 11px;
    color: #94a3b8;
    font-family: monospace;
  }

  /* MỤC THAY FILE THUẬT TOÁN (.PY / .JS) & KHÔI PHỤC GỐC */
  .algo-switcher-card {
    border: 1px solid rgba(56, 189, 248, 0.28);
    background: linear-gradient(155deg, rgba(16, 22, 34, 0.94), rgba(11, 15, 23, 0.96));
  }
  .sec-label {
    font-size: 11px;
    font-weight: 800;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.45px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .algo-status-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 10px;
    background: rgba(9, 12, 18, 0.85);
    border: 1px solid rgba(255, 255, 255, 0.08);
    margin-bottom: 10px;
  }
  .algo-active-name {
    font-size: 13px;
    font-weight: 800;
    color: #f8fafc;
  }
  .algo-active-sub {
    font-size: 11.5px;
    color: #94a3b8;
    margin-top: 2px;
  }
  .algo-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .algo-msg {
    font-size: 12px;
    margin-top: 8px;
    padding: 8px 10px;
    border-radius: 8px;
    display: none;
  }
  .algo-msg.ok {
    display: block;
    background: rgba(16, 185, 129, 0.14);
    border: 1px solid rgba(52, 211, 153, 0.35);
    color: #6ee7b7;
  }
  .algo-msg.err {
    display: block;
    background: rgba(244, 63, 94, 0.15);
    border: 1px solid rgba(251, 113, 133, 0.4);
    color: #fda4af;
  }

  /* HERO PHIÊN HIỆN TẠI ĐANG DỰ ĐOÁN */
  .pred-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    padding-bottom: 13px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  }
  .pred-tag {
    display: inline-block;
    font-size: 10.5px;
    font-weight: 800;
    color: #fde047;
    background: rgba(245, 158, 11, 0.15);
    border: 1px solid rgba(245, 158, 11, 0.35);
    padding: 3px 9px;
    border-radius: 6px;
    margin-bottom: 6px;
  }
  .session-num {
    font-size: 26px;
    font-weight: 900;
    color: #ffffff;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  .prev-session-sub {
    font-size: 12px;
    color: #94a3b8;
    margin-top: 3px;
  }
  .pred-right {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 6px;
  }
  .pred-pill {
    padding: 9px 26px;
    border-radius: 12px;
    font-size: 21px;
    font-weight: 900;
    letter-spacing: 0.8px;
  }
  .pred-tai {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.26), rgba(185, 28, 28, 0.22));
    color: #fca5a5;
    border: 1px solid rgba(248, 113, 113, 0.55);
    box-shadow: 0 4px 18px rgba(239, 68, 68, 0.2);
  }
  .pred-xiu {
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.26), rgba(4, 120, 87, 0.22));
    color: #6ee7b7;
    border: 1px solid rgba(52, 211, 153, 0.55);
    box-shadow: 0 4px 18px rgba(16, 185, 129, 0.2);
  }
  .pred-wait { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; }
  .conf-chip {
    font-size: 12px;
    font-weight: 800;
    color: #fde047;
  }

  .prob-bar-wrap { margin-top: 13px; }
  .prob-labels {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    font-weight: 800;
    margin-bottom: 6px;
  }
  .prob-track {
    height: 9px;
    border-radius: 999px;
    background: linear-gradient(90deg, #10b981, #34d399);
    overflow: hidden;
    display: flex;
  }
  .prob-fill-tai {
    height: 100%;
    background: linear-gradient(90deg, #ef4444, #f87171);
    transition: width 0.25s ease;
  }

  .meta-list {
    margin-top: 13px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 13px;
  }
  .meta-item { display: flex; justify-content: space-between; gap: 10px; }
  .meta-k { color: #94a3b8; white-space: nowrap; }
  .meta-v { color: #f8fafc; font-weight: 700; text-align: right; }
  .algo-tags {
    margin-top: 11px;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .algo-tag {
    font-size: 11px;
    font-weight: 700;
    padding: 4px 9px;
    border-radius: 7px;
    background: rgba(255, 255, 255, 0.05);
    color: #cbd5e1;
    border: 1px solid rgba(255, 255, 255, 0.09);
  }

  /* THỐNG KÊ VIP */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 9px;
  }
  @media (max-width: 620px) {
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .stat-box {
    background: rgba(11, 14, 21, 0.9);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 11px;
    padding: 11px 10px;
    text-align: center;
  }
  .stat-title { font-size: 11px; color: #94a3b8; margin-bottom: 4px; }
  .stat-val { font-size: 19px; font-weight: 900; font-family: monospace; }
  .stat-sub { font-size: 10.5px; color: #64748b; margin-top: 2px; }
  .c-win { color: #34d399; }
  .c-loss { color: #fb7185; }
  .c-info { color: #38bdf8; }
  .c-warn { color: #fde047; }

  /* CẦU 20 PHIÊN */
  .bead-strip {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .bead {
    min-width: 55px;
    padding: 6px 6px;
    border-radius: 9px;
    background: #0d1017;
    border: 1px solid rgba(255, 255, 255, 0.08);
    text-align: center;
    font-size: 11px;
  }
  .bead-id { font-size: 9.5px; color: #94a3b8; font-family: monospace; }
  .bead-res { font-weight: 900; font-size: 12px; margin-top: 2px; }
  .bead-t .bead-res { color: #fb7185; }
  .bead-x .bead-res { color: #34d399; }
  .bead-latest { border-color: #fde047; box-shadow: 0 0 0 1px rgba(253, 224, 71, 0.35); }

  /* BẢNG ĐỐI SOÁT */
  .table-wrap {
    width: 100%;
    overflow-x: auto;
    border-radius: 10px;
    border: 1px solid rgba(255, 255, 255, 0.08);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
    text-align: left;
  }
  th {
    background: #0e121b;
    color: #94a3b8;
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
    padding: 10px 11px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    white-space: nowrap;
  }
  td {
    padding: 9px 11px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    vertical-align: middle;
  }
  tr:last-child td { border-bottom: none; }
  tr.row-active { background: rgba(245, 158, 11, 0.08); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 700; }
  .tag-t {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 800;
    font-size: 11.5px;
    background: rgba(239, 68, 68, 0.2);
    color: #fca5a5;
  }
  .tag-x {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 800;
    font-size: 11.5px;
    background: rgba(16, 185, 129, 0.2);
    color: #6ee7b7;
  }
  .st-win {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 6px;
    font-weight: 800;
    font-size: 11px;
    background: rgba(16, 185, 129, 0.2);
    color: #34d399;
    border: 1px solid rgba(52, 211, 153, 0.35);
  }
  .st-loss {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 6px;
    font-weight: 800;
    font-size: 11px;
    background: rgba(244, 63, 94, 0.2);
    color: #fb7185;
    border: 1px solid rgba(251, 113, 133, 0.35);
  }
  .st-wait {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 6px;
    font-weight: 800;
    font-size: 11px;
    background: rgba(245, 158, 11, 0.18);
    color: #fde047;
    border: 1px solid rgba(253, 224, 71, 0.35);
  }
  .bridge-sub {
    display: block;
    font-size: 11px;
    color: #94a3b8;
    margin-top: 2px;
  }

  pre {
    background: #080a0f;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    padding: 11px;
    font-size: 11.5px;
    color: #cbd5e1;
    overflow-x: auto;
    max-height: 260px;
  }
</style>
</head>
<body>
<div class="container">
  <!-- HEADER VIP -->
  <div class="vip-card vip-card-gold header">
    <div class="brand-row">
      <div class="vip-crown">VIP</div>
      <div>
        <div class="title">LC79 SUPER HYBRID AI • VIP ANALYZER PRO</div>
        <div class="sub-title">Phân tích từng phiên realtime • Mã hóa mạng AES-256 • Thay thuật toán (.py / .js)</div>
      </div>
    </div>
    <div class="header-right">
      <div class="badge-online">
        <span class="pulse-dot"></span>
        <span id="statusBadge">ĐANG KẾT NỐI...</span>
      </div>
      <button type="button" class="btn btn-danger" onclick="logoutAdmin()">🚪 Đăng xuất</button>
    </div>
  </div>

  <!-- CHỌN CHẾ ĐỘ MD5 / TX -->
  <div class="mode-tabs">
    <button type="button" class="mode-btn ${safeMode === "md5" ? "active" : ""}" id="btnModeMd5" onclick="setMode('md5')">CHẾ ĐỘ MD5 (TXMD5)</button>
    <button type="button" class="mode-btn ${safeMode === "tx" ? "active" : ""}" id="btnModeTx" onclick="setMode('tx')">CHẾ ĐỘ TX (TXHU)</button>
  </div>

  <!-- KHỐI LINK API PHÂN TÍCH + LINK API GỐC CHƯA PHÂN TÍCH -->
  <div class="api-vip-showcase">
    <div class="api-showcase-head">
      <div class="api-showcase-title">
        <span>⚡</span>
        <span id="apiLabel">THÔNG TIN & ĐƯỜNG LINK API (${safeMode.toUpperCase()})</span>
      </div>
      <span class="api-mode-pill" id="apiModePill">ENDPOINT REALTIME 24/24</span>
    </div>

    <div class="api-info-list">
      <div class="api-info-row">
        <span class="api-info-icon">👑</span>
        <span class="api-info-label">Hệ thống API:</span>
        <span class="api-info-val" id="apiCardGame">LC79 • ${safeMode === "md5" ? "TXMD5" : "TXHU"} (JSON Chuẩn Tool)</span>
      </div>
      <div class="api-info-row">
        <span class="api-info-icon">⚙️</span>
        <span class="api-info-label">Thuật toán chạy:</span>
        <span class="api-info-val" style="color:#fde047;" id="apiCardEngine">SuperHybridAIEngine v3.0 (Gốc)</span>
      </div>
      <div class="api-info-row">
        <span class="api-info-icon">📊</span>
        <span class="api-info-label">Dữ liệu trả về:</span>
        <span class="api-info-val" id="apiCardSummary">Phiên đang dự đoán • Tổng Thắng/Thua • Chuỗi Max</span>
      </div>
    </div>

    <div class="sec-label" style="margin-bottom:5px;">
      <span>1. API ĐÃ PHÂN TÍCH AI (GIAO DIỆN PHIÊN CHUẨN MẪU)</span>
    </div>
    <div class="api-url-box">
      <input type="text" class="api-input" id="apiUrlInput" readonly value="" />
      <button type="button" class="btn btn-gold" id="btnCopy" onclick="copyTextById('apiUrlInput', 'btnCopy', '📋 Sao chép Link')">📋 Sao chép Link</button>
      <a class="btn" id="btnOpenRaw" href="/api/${safeMode}" target="_blank">🔗 Mở API Phiên</a>
    </div>

    <div class="sec-label" style="margin-bottom:5px;margin-top:8px;">
      <span>2. API GỐC CHƯA PHÂN TÍCH (DỮ LIỆU NGUYÊN BẢN TỪ NGUỒN)</span>
    </div>
    <div class="api-url-box" style="margin-bottom:0;">
      <input type="text" class="api-input" id="rawApiUrlInput" readonly value="" style="color:#34d399;" />
      <button type="button" class="btn btn-emerald" id="btnCopyRaw" onclick="copyTextById('rawApiUrlInput', 'btnCopyRaw', '📋 Sao chép API Gốc')">📋 Sao chép API Gốc</button>
      <a class="btn" id="btnOpenOriginRaw" href="/api/raw/${safeMode}" target="_blank">🔗 Mở API Gốc</a>
    </div>
  </div>

  <!-- QUẢN LÝ KHÓA / MỞ API (KHI KHÓA THÌ API KHÔNG THỂ XÀI) -->
  <div class="vip-card">
    <div class="sec-label">
      <span>🔐 QUẢN LÝ KHÓA / MỞ API (KHI KHÓA API SẼ NGỪNG PHỤC VỤ TOOL NGOÀI)</span>
      <div style="display:flex;gap:6px;">
        <button type="button" class="btn btn-danger" onclick="toggleApiLock('ALL_APIS', true)">🔒 Khóa Tất Cả</button>
        <button type="button" class="btn btn-emerald" onclick="toggleApiLock('ALL_APIS', false)">🔓 Mở Tất Cả</button>
      </div>
    </div>
    <div class="lock-grid" id="apiLockGrid">
      <div class="lock-item">
        <div>
          <div class="lock-name">API Phân Tích MD5</div>
          <div class="lock-path">/api/md5</div>
        </div>
        <button type="button" class="btn btn-emerald" id="lockBtn_md5" onclick="toggleApiLock('md5')">Đang mở</button>
      </div>
      <div class="lock-item">
        <div>
          <div class="lock-name">API Phân Tích TX</div>
          <div class="lock-path">/api/tx</div>
        </div>
        <button type="button" class="btn btn-emerald" id="lockBtn_tx" onclick="toggleApiLock('tx')">Đang mở</button>
      </div>
      <div class="lock-item">
        <div>
          <div class="lock-name">API Gốc Chưa Phân Tích (MD5)</div>
          <div class="lock-path">/api/raw/md5</div>
        </div>
        <button type="button" class="btn btn-emerald" id="lockBtn_raw_md5" onclick="toggleApiLock('raw_md5')">Đang mở</button>
      </div>
      <div class="lock-item">
        <div>
          <div class="lock-name">API Gốc Chưa Phân Tích (TX)</div>
          <div class="lock-path">/api/raw/tx</div>
        </div>
        <button type="button" class="btn btn-emerald" id="lockBtn_raw_tx" onclick="toggleApiLock('raw_tx')">Đang mở</button>
      </div>
      <div class="lock-item" style="grid-column: 1 / -1;">
        <div>
          <div class="lock-name">API Tổng Hợp (/api/all)</div>
          <div class="lock-path">/api/all</div>
        </div>
        <button type="button" class="btn btn-emerald" id="lockBtn_all" onclick="toggleApiLock('all')">Đang mở</button>
      </div>
    </div>
  </div>

  <!-- MỤC THAY FILE THUẬT TOÁN PHÂN TÍCH MỚI (.PY / .JS) & KHÔI PHỤC GỐC -->
  <div class="vip-card algo-switcher-card">
    <div class="sec-label">
      <span>🧠 QUẢN LÝ FILE THUẬT TOÁN PHÂN TÍCH (CHỈ NHẬN .PY & .JS)</span>
      <span style="color:#38bdf8;" id="pySupportTag">Đang kiểm tra môi trường...</span>
    </div>

    <div class="algo-status-bar">
      <div>
        <div class="algo-active-name" id="activeAlgoTitle">Đang chạy: Thuật Toán Gốc (SuperHybridAIEngine v3.0)</div>
        <div class="algo-active-sub" id="activeAlgoSub">Tự động lấy phiên, phân tích cầu và đối soát thắng/thua theo dữ liệu hệ thống.</div>
      </div>
      <div class="algo-actions">
        <input type="file" id="algoFileInput" accept=".py,.js" style="display:none;" onchange="handleAlgoFileSelected(event)" />
        <button type="button" class="btn btn-gold" onclick="triggerSelectAlgoFile()">📂 Thay File Thuật Toán (.py / .js)</button>
        <button type="button" class="btn btn-danger" id="btnRestoreAlgo" style="display:none;" onclick="restoreOriginalAlgo()">🗑️ Xóa & Khôi Phục Gốc</button>
      </div>
    </div>
    <div class="algo-msg" id="algoFeedbackMsg"></div>
  </div>

  <!-- PHIÊN HIỆN TẠI ĐANG DỰ ĐOÁN -->
  <div class="vip-card vip-card-gold">
    <div class="pred-top">
      <div>
        <div class="pred-tag" id="gameName">PHIÊN HIỆN TẠI ĐANG DỰ ĐOÁN • ${safeMode === "md5" ? "TXMD5" : "TXHU"}</div>
        <div class="session-num" id="nextSession">Phiên #---</div>
        <div class="prev-session-sub" id="lastResultVal">Phiên vừa chốt: đang tải...</div>
      </div>
      <div class="pred-right">
        <div class="pred-pill pred-wait" id="predSide">--</div>
        <div class="conf-chip" id="confVal">Độ tin cậy: --%</div>
      </div>
    </div>

    <div class="prob-bar-wrap">
      <div class="prob-labels">
        <span class="c-loss" id="taiPctLabel">TÀI: --%</span>
        <span class="c-win" id="xiuPctLabel">XỈU: --%</span>
      </div>
      <div class="prob-track">
        <div class="prob-fill-tai" id="taiBarFill" style="width: 50%;"></div>
      </div>
    </div>

    <div class="meta-list">
      <div class="meta-item"><span class="meta-k">Cấu trúc cầu / Nguồn phân tích:</span><span class="meta-v" id="bridgeVal">Đang dò cầu...</span></div>
      <div class="meta-item"><span class="meta-k">Khuyến nghị hệ thống:</span><span class="meta-v" id="adviceVal">--</span></div>
    </div>
    <div class="algo-tags" id="algoTags"></div>
  </div>

  <!-- THỐNG KÊ TỔNG THẮNG THUA & CHUỖI MAX -->
  <div class="vip-card">
    <div class="sec-label">
      <span>THỐNG KÊ ĐỐI SOÁT REALTIME</span>
      <span class="c-warn" id="winRateBadge">Tỷ lệ thắng: 0.0%</span>
    </div>
    <div class="stats-grid">
      <div class="stat-box">
        <div class="stat-title">Tổng Thắng</div>
        <div class="stat-val c-win" id="statWins">0</div>
        <div class="stat-sub" id="statCurWin">Đang thắng: 0</div>
      </div>
      <div class="stat-box">
        <div class="stat-title">Tổng Thua</div>
        <div class="stat-val c-loss" id="statLosses">0</div>
        <div class="stat-sub" id="statCurLoss">Đang thua: 0</div>
      </div>
      <div class="stat-box">
        <div class="stat-title">Chuỗi Thắng Cao Nhất</div>
        <div class="stat-val c-info" id="statMaxWin">0</div>
        <div class="stat-sub">Kỷ lục Win</div>
      </div>
      <div class="stat-box">
        <div class="stat-title">Chuỗi Thua Cao Nhất</div>
        <div class="stat-val c-loss" id="statMaxLoss">0</div>
        <div class="stat-sub">Kỷ lục Loss</div>
      </div>
    </div>
  </div>

  <!-- BẢNG PHÂN TÍCH & ĐỐI SOÁT TRÊN TỪNG PHIÊN -->
  <div class="vip-card">
    <div class="sec-label">
      <span>PHÂN TÍCH & ĐỐI SOÁT CHI TIẾT TRÊN TỪNG PHIÊN</span>
      <span id="analyzedCountLbl">Đã đối soát: 0 phiên</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Phiên</th>
            <th>Dự Đoán & Thuật Toán</th>
            <th>Kết Quả Về</th>
            <th>Trạng Thái</th>
          </tr>
        </thead>
        <tbody id="sessionTableBody">
          <tr><td colspan="4" style="text-align:center;color:#94a3b8;">Đang tải dữ liệu từng phiên...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- LỊCH SỬ 20 PHIÊN GẦN NHẤT -->
  <div class="vip-card">
    <div class="sec-label">
      <span>20 PHIÊN KẾT QUẢ GẦN NHẤT</span>
      <span>Mới nhất bên trái</span>
    </div>
    <div class="bead-strip" id="beadStrip"></div>
  </div>

  <!-- XEM TRƯỚC JSON API BÁO RA NGOÀI -->
  <div class="vip-card">
    <div class="sec-label">
      <span>DỮ LIỆU JSON API BÁO RA TOOL NGOÀI</span>
      <span>Nhật ký mạng đã mã hóa AES-256-GCM</span>
    </div>
    <pre id="jsonPreview">Đang tải dữ liệu...</pre>
  </div>
</div>

<script>
  let currentMode = "${safeMode}";
  const NET_KEY_HEX = "${netKeyHex}";
  let currentLockState = {};

  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  async function encryptNetBody(obj) {
    if (!NET_KEY_HEX || !window.crypto || !window.crypto.subtle) return obj;
    const key = await crypto.subtle.importKey("raw", hexToBytes(NET_KEY_HEX), { name: "AES-GCM" }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = new TextEncoder().encode(JSON.stringify(obj));
    const encBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
    const encBytes = new Uint8Array(encBuf);
    const cipherBytes = encBytes.slice(0, encBytes.length - 16);
    const tagBytes = encBytes.slice(encBytes.length - 16);
    return {
      _enc: 1,
      v: "LC79-NET-AES256",
      ts: Date.now(),
      iv: bytesToB64(iv),
      tag: bytesToB64(tagBytes),
      d: bytesToB64(cipherBytes),
    };
  }

  async function decryptNetBody(pkt) {
    if (!pkt || pkt._enc !== 1) return pkt;
    const key = await crypto.subtle.importKey("raw", hexToBytes(NET_KEY_HEX), { name: "AES-GCM" }, false, ["decrypt"]);
    const iv = b64ToBytes(pkt.iv);
    const cipherBytes = b64ToBytes(pkt.d);
    const tagBytes = b64ToBytes(pkt.tag);
    const combined = new Uint8Array(cipherBytes.length + tagBytes.length);
    combined.set(cipherBytes, 0);
    combined.set(tagBytes, cipherBytes.length);
    const decBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, combined);
    return JSON.parse(new TextDecoder().decode(decBuf));
  }

  async function secureAdminFetch(url, options = {}) {
    const headers = Object.assign({}, options.headers || {}, {
      "X-Net-Encrypted": "1"
    });
    let body = options.body;
    if (body && typeof body === "string") {
      try {
        const parsed = JSON.parse(body);
        const encPkt = await encryptNetBody(parsed);
        body = JSON.stringify(encPkt);
      } catch (_) {}
    }
    const res = await fetch(url, Object.assign({}, options, { headers, body, cache: "no-store" }));
    if (res.status === 401) {
      window.location.href = "/login";
      throw new Error("Phiên đăng nhập đã hết hạn");
    }
    const rawJson = await res.json();
    const data = await decryptNetBody(rawJson);
    return { res, data };
  }

  async function logoutAdmin() {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
  }

  function getApiFullUrl(mode) {
    return window.location.origin + "/api/" + mode;
  }

  function getRawApiFullUrl(mode) {
    return window.location.origin + "/api/raw/" + mode;
  }

  function updateApiLinkUI() {
    document.getElementById("apiUrlInput").value = getApiFullUrl(currentMode);
    document.getElementById("rawApiUrlInput").value = getRawApiFullUrl(currentMode);
    document.getElementById("apiLabel").textContent =
      "THÔNG TIN & ĐƯỜNG LINK API (" + currentMode.toUpperCase() + ")";
    document.getElementById("apiCardGame").textContent =
      "LC79 • " + (currentMode === "md5" ? "TXMD5" : "TXHU") + " (JSON Chuẩn Tool)";
    document.getElementById("btnOpenRaw").href = "/api/" + currentMode;
    document.getElementById("btnOpenOriginRaw").href = "/api/raw/" + currentMode;
    document.getElementById("btnModeMd5").classList.toggle("active", currentMode === "md5");
    document.getElementById("btnModeTx").classList.toggle("active", currentMode === "tx");
  }

  function setMode(mode) {
    currentMode = mode === "tx" ? "tx" : "md5";
    const url = new URL(window.location.href);
    url.searchParams.set("mode", currentMode);
    window.history.replaceState({}, "", url.toString());
    updateApiLinkUI();
    refreshData();
  }

  async function copyTextById(inputId, btnId, defaultLabel) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    try {
      await navigator.clipboard.writeText(input.value);
    } catch (e) {
      input.select();
      document.execCommand("copy");
    }
    btn.textContent = "✅ Đã sao chép!";
    setTimeout(() => { btn.textContent = defaultLabel; }, 1600);
  }

  function renderApiLocks(locks) {
    if (!locks) return;
    currentLockState = locks;
    const keys = ["md5", "tx", "raw_md5", "raw_tx", "all"];
    for (const k of keys) {
      const btn = document.getElementById("lockBtn_" + k);
      if (!btn) continue;
      const isLocked = Boolean(locks[k]);
      if (isLocked) {
        btn.className = "btn btn-danger";
        btn.textContent = "🔒 Đang khóa (Bấm để mở)";
      } else {
        btn.className = "btn btn-emerald";
        btn.textContent = "🔓 Đang mở (Bấm để khóa)";
      }
    }
  }

  async function toggleApiLock(key, forceVal) {
    try {
      const nextLocked = typeof forceVal === "boolean" ? forceVal : !Boolean(currentLockState[key]);
      const { res, data } = await secureAdminFetch("/api/admin/locks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, locked: nextLocked }),
      });
      if (res.ok && data.ok) {
        renderApiLocks(data.locks);
      }
    } catch (err) {
      console.error(err);
    }
  }

  function showAlgoMsg(text, isError = false) {
    const box = document.getElementById("algoFeedbackMsg");
    box.textContent = text;
    box.className = "algo-msg " + (isError ? "err" : "ok");
  }

  function triggerSelectAlgoFile() {
    const inp = document.getElementById("algoFileInput");
    inp.value = "";
    inp.click();
  }

  async function handleAlgoFileSelected(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    const nameLower = file.name.toLowerCase();
    if (!nameLower.endsWith(".py") && !nameLower.endsWith(".js")) {
      showAlgoMsg("Chỉ chấp nhận tệp định dạng .py hoặc .js!", true);
      return;
    }

    try {
      const content = await file.text();
      showAlgoMsg("Đang nạp và kích hoạt thuật toán từ tệp " + file.name + "...", false);
      const { res, data: result } = await secureAdminFetch("/api/algorithm/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fileName: file.name, content }),
      });
      if (!res.ok || !result.ok) {
        showAlgoMsg(result.error || "Không thể nạp tệp thuật toán.", true);
        return;
      }
      showAlgoMsg("Đã kích hoạt thành công file thuật toán: " + file.name + " (Đã dừng thuật toán cũ).", false);
      await refreshData();
    } catch (err) {
      showAlgoMsg("Lỗi tải tệp lên server: " + err.message, true);
    }
  }

  async function restoreOriginalAlgo() {
    try {
      const { res, data: result } = await secureAdminFetch("/api/algorithm/reset", { method: "POST" });
      if (!res.ok || !result.ok) {
        showAlgoMsg(result.error || "Lỗi khi khôi phục thuật toán gốc.", true);
        return;
      }
      showAlgoMsg("Đã xóa file thuật toán tùy chỉnh và khôi phục thuật toán gốc SuperHybridAIEngine v3.0.", false);
      await refreshData();
    } catch (err) {
      showAlgoMsg("Lỗi kết nối khi khôi phục: " + err.message, true);
    }
  }

  function updateAlgorithmPanel(algoStatus) {
    if (!algoStatus) return;
    const pyTag = document.getElementById("pySupportTag");
    pyTag.textContent = algoStatus.python_supported
      ? "Hỗ trợ: .JS & .PY (Sẵn sàng)"
      : "Hỗ trợ: .JS (Server chưa cài Python)";

    const titleEl = document.getElementById("activeAlgoTitle");
    const subEl = document.getElementById("activeAlgoSub");
    const restoreBtn = document.getElementById("btnRestoreAlgo");
    const apiCardEng = document.getElementById("apiCardEngine");

    if (algoStatus.active) {
      titleEl.textContent = "Đang chạy Tool Mới: " + algoStatus.file_name + " (Đã dừng thuật toán gốc)";
      titleEl.style.color = "#fde047";
      subEl.textContent = "Web tự lấy phiên & đối soát thắng/thua theo dữ liệu cũ nhưng dự đoán bằng " + algoStatus.file_name;
      restoreBtn.style.display = "inline-flex";
      apiCardEng.textContent = "Tool Tùy Chỉnh (" + algoStatus.file_name + ")";
      if (algoStatus.last_error) {
        showAlgoMsg("Cảnh báo chạy file " + algoStatus.file_name + ": " + algoStatus.last_error, true);
      }
    } else {
      titleEl.textContent = "Đang chạy: Thuật Toán Gốc (SuperHybridAIEngine v3.0)";
      titleEl.style.color = "#f8fafc";
      subEl.textContent = "Tự động lấy phiên, phân tích cầu và đối soát thắng/thua theo dữ liệu hệ thống.";
      restoreBtn.style.display = "none";
      apiCardEng.textContent = "SuperHybridAIEngine v3.0 (Thuật Toán Gốc)";
    }
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderSessionTable(data) {
    const tbody = document.getElementById("sessionTableBody");
    const rows = [];

    if (data.phien_hien_tai_dang_du_doan) {
      const predClass = data.du_doan === "TÀI" ? "tag-t" : "tag-x";
      rows.push(
        '<tr class="row-active">' +
          '<td class="mono">#' + escapeHtml(data.phien_hien_tai_dang_du_doan) +
            '<span class="bridge-sub" style="color:#fde047;">Đang dự đoán</span></td>' +
          '<td><span class="' + predClass + '">' + escapeHtml(data.du_doan || "--") +
            ' (' + escapeHtml(data.do_tin_cay ?? "--") + '%)</span>' +
            '<span class="bridge-sub">' + escapeHtml(data.cau || "") + '</span></td>' +
          '<td style="color:#94a3b8;">Đang chờ mở bát...</td>' +
          '<td><span class="st-wait">ĐANG CHỜ</span></td>' +
        '</tr>'
      );
    }

    const logs = Array.isArray(data.lich_su_doi_soat) ? data.lich_su_doi_soat : [];
    for (const item of logs) {
      const pClass = item.du_doan === "TÀI" ? "tag-t" : "tag-x";
      const rClass = item.ket_qua === "TÀI" ? "tag-t" : "tag-x";
      const stClass = item.trang_thai === "THẮNG" ? "st-win" : "st-loss";
      const dices = Array.isArray(item.xuc_xac) && item.xuc_xac.length === 3
        ? ("[" + item.xuc_xac.join("-") + "] ")
        : "";
      rows.push(
        '<tr>' +
          '<td class="mono">#' + escapeHtml(item.phien) + '</td>' +
          '<td><span class="' + pClass + '">' + escapeHtml(item.du_doan) +
            (item.do_tin_cay ? (' (' + escapeHtml(item.do_tin_cay) + '%)') : '') + '</span>' +
            '<span class="bridge-sub">' + escapeHtml(item.cau || "") + '</span></td>' +
          '<td><span class="' + rClass + '">' + escapeHtml(item.ket_qua) + '</span> ' +
            '<span class="mono" style="font-size:11.5px;color:#cbd5e1;">' + escapeHtml(dices + item.tong_diem + "đ") + '</span></td>' +
          '<td><span class="' + stClass + '">' + escapeHtml(item.trang_thai) + '</span></td>' +
        '</tr>'
      );
    }

    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#94a3b8;">Chưa có dữ liệu phiên</td></tr>';
    } else {
      tbody.innerHTML = rows.join("");
    }
  }

  function renderBeadStrip(list) {
    const strip = document.getElementById("beadStrip");
    if (!Array.isArray(list) || !list.length) {
      strip.innerHTML = "";
      return;
    }
    strip.innerHTML = list.slice(0, 20).map((item, idx) => {
      const isTai = item.resultTruyenThong === "TAI" || Number(item.point) >= 11;
      const cls = isTai ? "bead bead-t" : "bead bead-x";
      const latestCls = idx === 0 ? " bead-latest" : "";
      const shortId = String(item.id).slice(-4);
      return '<div class="' + cls + latestCls + '" title="Phiên #' + escapeHtml(item.id) + ': ' + escapeHtml(item.point) + ' điểm">' +
        '<div class="bead-id">#' + escapeHtml(shortId) + '</div>' +
        '<div class="bead-res">' + (isTai ? 'T' : 'X') + ' • ' + escapeHtml(item.point) + '</div>' +
      '</div>';
    }).join("");
  }

  async function refreshData() {
    try {
      const { data: wrap } = await secureAdminFetch("/api/admin/state?mode=" + currentMode);
      const data = wrap.channel;
      renderApiLocks(wrap.locks);

      document.getElementById("statusBadge").textContent =
        data.status === "ok" ? "ONLINE • BẢO MẬT AES-256" : "ĐANG KHỞI TẠO...";
      document.getElementById("gameName").textContent =
        "PHIÊN HIỆN TẠI ĐANG DỰ ĐOÁN • " + (data.game || ("LC79 • " + currentMode.toUpperCase()));
      document.getElementById("nextSession").textContent =
        data.phien_hien_tai_dang_du_doan ? ("Phiên #" + data.phien_hien_tai_dang_du_doan) : "Phiên #---";

      updateAlgorithmPanel(data.thuat_toan_dang_chay);

      const predEl = document.getElementById("predSide");
      predEl.classList.remove("pred-tai", "pred-xiu", "pred-wait");
      if (data.du_doan === "TÀI") {
        predEl.textContent = "TÀI";
        predEl.classList.add("pred-tai");
      } else if (data.du_doan === "XỈU") {
        predEl.textContent = "XỈU";
        predEl.classList.add("pred-xiu");
      } else {
        predEl.textContent = "--";
        predEl.classList.add("pred-wait");
      }

      document.getElementById("confVal").textContent =
        "Độ tin cậy: " + (data.do_tin_cay !== null ? (data.do_tin_cay + "%") : "--%");

      const taiPct = Number(data.ty_le_tai ?? 50);
      const xiuPct = Number(data.ty_le_xiu ?? 50);
      document.getElementById("taiPctLabel").textContent = "TÀI: " + taiPct + "%";
      document.getElementById("xiuPctLabel").textContent = "XỈU: " + xiuPct + "%";
      document.getElementById("taiBarFill").style.width = Math.max(5, Math.min(95, taiPct)) + "%";

      document.getElementById("bridgeVal").textContent = data.cau || "--";
      document.getElementById("adviceVal").textContent = data.khuyen_nghi || "--";

      const algoBox = document.getElementById("algoTags");
      if (Array.isArray(data.thuat_toan)) {
        algoBox.innerHTML = data.thuat_toan.map(t => '<span class="algo-tag">' + escapeHtml(t) + '</span>').join("");
      }

      if (data.ket_qua_vua_ve) {
        const k = data.ket_qua_vua_ve;
        const dices = Array.isArray(k.xuc_xac) && k.xuc_xac.length ? ("[" + k.xuc_xac.join("-") + "] ") : "";
        document.getElementById("lastResultVal").textContent =
          "Phiên vừa chốt #" + k.phien + ": " + dices + k.tong_diem + " điểm (" + k.ket_qua + ")";
      }

      document.getElementById("statWins").textContent = data.tong_thang ?? 0;
      document.getElementById("statLosses").textContent = data.tong_thua ?? 0;
      document.getElementById("statCurWin").textContent = "Chuỗi thắng hiện tại: " + (data.chuoi_thang_hien_tai ?? 0);
      document.getElementById("statCurLoss").textContent = "Chuỗi thua hiện tại: " + (data.chuoi_thua_hien_tai ?? 0);
      document.getElementById("statMaxWin").textContent = data.chuoi_thang_cao_nhat ?? 0;
      document.getElementById("statMaxLoss").textContent = data.chuoi_thua_cao_nhat ?? 0;
      document.getElementById("winRateBadge").textContent =
        (data.tong_thang_thua || "0 Thắng / 0 Thua") + " (" + (data.ty_le_thang || "0.0%") + ")";
      document.getElementById("analyzedCountLbl").textContent =
        "Đã đối soát: " + (data.tong_phan_tich ?? 0) + " phiên";

      document.getElementById("apiCardSummary").textContent =
        "Phiên #" + (data.phien_hien_tai_dang_du_doan || "---") + " • " +
        (data.tong_thang_thua || "0 Thắng / 0 Thua") + " • " +
        (data.chuoi_thang_thua_cao_nhat || "Thắng max: 0 | Thua max: 0");

      renderSessionTable(data);
      renderBeadStrip(data.list);

      const previewObj = {
        id: data.id,
        version: data.version,
        type: data.type,
        thong_ke: data.thong_ke,
        total: data.total,
        data: Array.isArray(data.data) ? data.data.slice(0, 4) : [],
      };
      document.getElementById("jsonPreview").textContent = JSON.stringify(previewObj, null, 2);
    } catch (err) {
      document.getElementById("statusBadge").textContent = "LỖI KẾT NỐI";
    }
  }

  updateApiLinkUI();
  refreshData();
  setInterval(refreshData, 2000);
</script>
</body>
</html>`;
}

// ============================================================================
// HTTP SERVER ROUTING (PHÂN TÁCH CÔNG KHAI API VS QUẢN TRỊ ĐĂNG NHẬP)
// ============================================================================
function sendApiLocked(res, apiName) {
    return sendJson(res, 423, {
        status: "locked",
        locked: true,
        error: `API [${apiName}] hiện đang bị Admin khóa tạm thời. Không thể sử dụng.`,
    });
}

function wantsHtmlBrowserView(req, formatParam) {
    if (formatParam === "json" || formatParam === "raw") return false;
    if (formatParam === "html" || formatParam === "ui") return true;
    const accept = String(req.headers.accept || "");
    return accept.includes("text/html");
}

function sendProtectedHtml(res, rawHtml, extraHeaders = {}) {
    const shielded = obfuscateHtmlResponse(rawHtml);
    res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        ...extraHeaders,
    });
    return res.end(shielded);
}

function sendAdminJson(req, res, sessionObj, statusCode, payload) {
    if (req.headers["x-net-encrypted"] === "1" && sessionObj && sessionObj.netKeyHex) {
        const encrypted = encryptNetworkPacket(payload, sessionObj.netKeyHex);
        return sendJson(res, statusCode, encrypted, false);
    }
    return sendJson(res, statusCode, payload);
}

async function readAdminJsonBody(req, sessionObj) {
    const rawBody = await readJsonBody(req);
    if (rawBody && rawBody._enc === 1 && sessionObj && sessionObj.netKeyHex) {
        return decryptNetworkPacket(rawBody, sessionObj.netKeyHex);
    }
    return rawBody;
}

const server = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
        res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Token, X-Net-Encrypted",
        });
        return res.end();
    }

    const parsedUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = parsedUrl.pathname.replace(/\/+$/, "") || "/";
    const formatParam = (parsedUrl.searchParams.get("format") || "").toLowerCase();
    const modeParam = (parsedUrl.searchParams.get("mode") || "md5").toLowerCase();

    // 1. Endpoint Đăng nhập / Đăng xuất Admin
    if (pathname === "/login") {
        const existing = getAuthSession(req);
        if (existing) {
            res.writeHead(302, { Location: "/" });
            return res.end();
        }
        return sendProtectedHtml(res, renderLoginHtml());
    }

    if (pathname === "/api/auth/login" && req.method === "POST") {
        try {
            const body = await readJsonBody(req, 16384);
            const u = String(body.username || "").trim();
            const p = String(body.password || "");
            if (u === ADMIN_USER && p === ADMIN_PASS) {
                const sess = createAuthSession(u);
                res.writeHead(200, {
                    "Content-Type": "application/json; charset=utf-8",
                    "Set-Cookie": `lc79_admin_sid=${encodeURIComponent(sess.token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
                    "Cache-Control": "no-store",
                });
                return res.end(JSON.stringify({ ok: true, user: u }));
            }
            return sendJson(res, 401, { ok: false, error: "Tài khoản hoặc mật khẩu không chính xác!" });
        } catch (err) {
            return sendJson(res, 400, { ok: false, error: err.message });
        }
    }

    if (pathname === "/api/auth/logout") {
        const sess = getAuthSession(req);
        if (sess) activeSessions.delete(sess.token);
        res.writeHead(200, {
            "Content-Type": "application/json; charset=utf-8",
            "Set-Cookie": "lc79_admin_sid=; Path=/; HttpOnly; Max-Age=0",
        });
        return res.end(JSON.stringify({ ok: true }));
    }

    // 2. Các API công khai (TRỪ API không cần đăng nhập, nhưng chịu kiểm soát Khóa/Mở)
    if (pathname === "/health") {
        return sendJson(res, 200, {
            status: "ok",
            uptime_seconds: Math.floor(process.uptime()),
            locks: apiLockManager.getStatus(),
            algorithm: customAlgoManager.getStatus(),
            tx_session: analyzers.tx.currentSessionId,
            tx_predicting_session: analyzers.tx.nextSession,
            md5_session: analyzers.md5.currentSessionId,
            md5_predicting_session: analyzers.md5.nextSession,
        });
    }

    // API Gốc chưa phân tích (MD5 & TX & ALL)
    if (pathname === "/api/raw/tx" || pathname === "/api/origin/tx") {
        if (apiLockManager.isLocked("raw_tx")) return sendApiLocked(res, "RAW TX");
        if (!analyzers.tx.txHistory.length) await analyzers.tx.fetchAndAnalyze();
        const payload = analyzers.tx.toRawApiResponse();
        if (wantsHtmlBrowserView(req, formatParam)) {
            return sendProtectedHtml(res, renderApiSessionPageHtml("raw-tx", payload));
        }
        return sendJson(res, 200, payload);
    }

    if (pathname === "/api/raw/md5" || pathname === "/api/origin/md5") {
        if (apiLockManager.isLocked("raw_md5")) return sendApiLocked(res, "RAW MD5");
        if (!analyzers.md5.txHistory.length) await analyzers.md5.fetchAndAnalyze();
        const payload = analyzers.md5.toRawApiResponse();
        if (wantsHtmlBrowserView(req, formatParam)) {
            return sendProtectedHtml(res, renderApiSessionPageHtml("raw-md5", payload));
        }
        return sendJson(res, 200, payload);
    }

    if (pathname === "/api/raw/all" || pathname === "/api/origin/all") {
        if (apiLockManager.isLocked("raw_md5") && apiLockManager.isLocked("raw_tx")) {
            return sendApiLocked(res, "RAW ALL");
        }
        if (!analyzers.tx.txHistory.length || !analyzers.md5.txHistory.length) {
            await pollAllChannels();
        }
        const payload = {
            status: "ok",
            type: "RAW_UNANALYZED_ORIGIN_ALL",
            tx: apiLockManager.isLocked("raw_tx") ? { status: "locked" } : analyzers.tx.toRawApiResponse(),
            md5: apiLockManager.isLocked("raw_md5") ? { status: "locked" } : analyzers.md5.toRawApiResponse(),
        };
        if (wantsHtmlBrowserView(req, formatParam)) {
            return sendProtectedHtml(res, renderApiSessionPageHtml("raw-all", payload));
        }
        return sendJson(res, 200, payload);
    }

    // API Phân tích TX (Trả về giao diện JSON chuẩn ảnh mẫu khi mở trên trình duyệt, hoặc JSON thuần cho Tool)
    if (pathname === "/api/tx" || pathname === "/tx" || pathname === "/v1/tx/sessions") {
        if (apiLockManager.isLocked("tx")) return sendApiLocked(res, "TX");
        if (!analyzers.tx.prediction) await analyzers.tx.fetchAndAnalyze();
        const payload = analyzers.tx.toApiResponse();
        if (wantsHtmlBrowserView(req, formatParam)) {
            return sendProtectedHtml(res, renderApiSessionPageHtml("tx", payload));
        }
        return sendJson(res, 200, payload);
    }

    // API Phân tích MD5 (Trả về giao diện JSON chuẩn ảnh mẫu khi mở trên trình duyệt, hoặc JSON thuần cho Tool)
    if (pathname === "/api/md5" || pathname === "/md5" || pathname === "/v1/txmd5/sessions") {
        if (apiLockManager.isLocked("md5")) return sendApiLocked(res, "MD5");
        if (!analyzers.md5.prediction) await analyzers.md5.fetchAndAnalyze();
        const payload = analyzers.md5.toApiResponse();
        if (wantsHtmlBrowserView(req, formatParam)) {
            return sendProtectedHtml(res, renderApiSessionPageHtml("md5", payload));
        }
        return sendJson(res, 200, payload);
    }

    // API Tổng hợp
    if (pathname === "/api/all" || pathname === "/api" || (pathname === "/" && formatParam === "json")) {
        if (apiLockManager.isLocked("all")) return sendApiLocked(res, "ALL");
        if (!analyzers.tx.prediction || !analyzers.md5.prediction) {
            await pollAllChannels();
        }
        const payload = {
            status: "ok",
            service: "LC79 Super Hybrid AI Analyzer v4.1 VIP (TX & MD5)",
            thuat_toan_dang_chay: customAlgoManager.getStatus(),
            endpoints: {
                tx: "/api/tx",
                md5: "/api/md5",
                raw_tx: "/api/raw/tx",
                raw_md5: "/api/raw/md5",
                raw_all: "/api/raw/all",
                all: "/api/all",
                health: "/health",
            },
            tx: apiLockManager.isLocked("tx") ? { status: "locked", error: "API TX đang bị khóa" } : analyzers.tx.toApiResponse(),
            md5: apiLockManager.isLocked("md5") ? { status: "locked", error: "API MD5 đang bị khóa" } : analyzers.md5.toApiResponse(),
        };
        if (wantsHtmlBrowserView(req, formatParam) && pathname !== "/") {
            return sendProtectedHtml(res, renderApiSessionPageHtml("all", payload));
        }
        return sendJson(res, 200, payload);
    }

    // 3. Các Route Quản trị yêu cầu đăng nhập Admin (vkhanh / 2011)
    const adminSess = getAuthSession(req);
    if (!adminSess) {
        if (pathname.startsWith("/api/")) {
            return sendJson(res, 401, { ok: false, error: "Chưa đăng nhập Admin." });
        }
        res.writeHead(302, { Location: "/login" });
        return res.end();
    }

    if (pathname === "/api/admin/state" && req.method === "GET") {
        const ch = modeParam === "tx" ? analyzers.tx : analyzers.md5;
        if (!ch.prediction) await ch.fetchAndAnalyze();
        return sendAdminJson(req, res, adminSess, 200, {
            ok: true,
            locks: apiLockManager.getStatus(),
            channel: ch.toApiResponse(),
        });
    }

    if (pathname === "/api/admin/locks" && req.method === "POST") {
        try {
            const body = await readAdminJsonBody(req, adminSess);
            const locks = apiLockManager.setLock(body.key, body.locked);
            return sendAdminJson(req, res, adminSess, 200, { ok: true, locks });
        } catch (err) {
            return sendAdminJson(req, res, adminSess, 400, { ok: false, error: err.message });
        }
    }

    if (pathname === "/api/algorithm/status" && req.method === "GET") {
        return sendAdminJson(req, res, adminSess, 200, {
            ok: true,
            algorithm: customAlgoManager.getStatus(),
        });
    }

    if (pathname === "/api/algorithm/upload" && req.method === "POST") {
        try {
            const body = await readAdminJsonBody(req, adminSess);
            const status = customAlgoManager.uploadAlgorithm(body.fileName, body.content);
            recomputeAllChannelsNow();
            return sendAdminJson(req, res, adminSess, 200, {
                ok: true,
                message: `Đã nạp và kích hoạt thuật toán từ ${status.file_name}`,
                algorithm: status,
            });
        } catch (err) {
            return sendAdminJson(req, res, adminSess, 400, {
                ok: false,
                error: err.message,
            });
        }
    }

    if ((pathname === "/api/algorithm/reset" || pathname === "/api/algorithm") && (req.method === "POST" || req.method === "DELETE")) {
        const status = customAlgoManager.removeAndRestoreOriginal();
        recomputeAllChannelsNow();
        return sendAdminJson(req, res, adminSess, 200, {
            ok: true,
            message: "Đã xóa file thuật toán tùy chỉnh và khôi phục thuật toán gốc.",
            algorithm: status,
        });
    }

    if (pathname === "/") {
        if (!analyzers.tx.prediction || !analyzers.md5.prediction) {
            await pollAllChannels();
        }
        const html = renderDashboardHtml(modeParam, adminSess);
        return sendProtectedHtml(res, html);
    }

    return sendJson(res, 404, {
        status: "error",
        message: "Endpoint không tồn tại. Sử dụng /, /api/tx, /api/md5, /api/raw/tx, /api/raw/md5 hoặc /api/all",
    });
});

async function startServer() {
    await pollAllChannels();
    setInterval(pollAllChannels, POLL_INTERVAL_MS);

    server.listen(PORT, "0.0.0.0", () => {
        console.log(`[LC79-AI-API] Server đang chạy tại cổng ${PORT}`);
        console.log(`[LC79-AI-API] Web UI      : http://0.0.0.0:${PORT}/`);
        console.log(`[LC79-AI-API] Endpoint TX : http://0.0.0.0:${PORT}/api/tx`);
        console.log(`[LC79-AI-API] Endpoint MD5: http://0.0.0.0:${PORT}/api/md5`);
        console.log(`[LC79-AI-API] API Gốc TX  : http://0.0.0.0:${PORT}/api/raw/tx`);
        console.log(`[LC79-AI-API] API Gốc MD5 : http://0.0.0.0:${PORT}/api/raw/md5`);
    });
}

if (require.main === module) {
    startServer();
}

module.exports = {
    SuperHybridAIEngine,
    ChannelAnalyzer,
    CustomAlgorithmManager,
    ApiLockManager,
    customAlgoManager,
    apiLockManager,
    analyzers,
    parseLines,
    extractFeatures,
    detectPatternType,
    predictFromPattern,
    predictTaiXiuClassic,
};
