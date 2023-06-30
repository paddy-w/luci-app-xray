#!/usr/bin/ucode
"use strict";

import { popen, stat } from "fs";
import { load_config } from "/usr/share/xray/common/config.mjs";

const http = function () {
    if (stat("/usr/share/ucode/http.uc") == null) {
        return {
            get: function () {
                return {
                    status: "Not Found",
                    code: 404,
                    headers: [],
                    body: `"ucode-mod-http not found"`
                };
            }
        };
    }
    return require("http");
}();

const config = load_config();
const proxy = config[filter(keys(config), k => config[k][".type"] == "general")[0]];

function xray_api_json(command) {
    const result = popen(`${proxy.xray_bin} api ${command} -s 127.0.0.1:8080`, 'r');
    const parsed = json(result);
    result.close();
    return parsed;
}

/*
 * todo: build debugvars manually via xray api command if http module is not available
 * will be slow but works so far so good
 */
return {
    xray: {
        statsquery: {
            call: function (request) {
                request.reply(xray_api_json("statsquery"));
            }
        },
        statssys: {
            call: function (request) {
                request.reply(xray_api_json("statssys"));
            }
        },
        restartlogger: {
            call: function (request) {
                request.reply(xray_api_json("restartlogger"));
            }
        },
        debugvars: {
            call: function (request) {
                const result = http.get("127.0.0.1", proxy["metrics_server_port"] || 18888, "/debug/vars", []);
                request.reply({
                    status: result.status,
                    code: result.code,
                    headers: result.headers,
                    json: json(result.body)
                });
            }
        }
    }
};
