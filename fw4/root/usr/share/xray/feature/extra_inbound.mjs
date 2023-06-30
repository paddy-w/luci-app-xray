"use strict";

import { socks_inbound, http_inbound, dokodemo_inbound } from "./inbound.mjs";

export function extra_inbounds(proxy, extra_inbound) {
    let result = [];
    for (let v in extra_inbound) {
        const tag = `extra_inbound_${v[".name"]}`;
        if (v["inbound_type"] == "http") {
            push(result, http_inbound(v["inbound_addr"] || "0.0.0.0", v["inbound_port"], tag));
        } else if (v["inbound_type"] == "socks5") {
            push(result, socks_inbound(v["inbound_addr"] || "0.0.0.0", v["inbound_port"], tag));
        } else if (v["inbound_type"] == "tproxy_tcp") {
            push(result, dokodemo_inbound(v["inbound_addr"] || "0.0.0.0", v["inbound_port"], tag, proxy["tproxy_sniffing"], proxy["route_only"], ["http", "tls"], "tcp", "tproxy"));
        } else if (v["inbound_type"] == "tproxy_udp") {
            push(result, dokodemo_inbound(v["inbound_addr"] || "0.0.0.0", v["inbound_port"], tag, proxy["tproxy_sniffing"], proxy["route_only"], ["quic"], "udp", "tproxy"));
        } else {
            die(`unknown inbound type ${v["inbound_type"]}`);
        }
    }
    return result;
};

export function extra_inbound_rules(extra_inbound) {
    let result = [];
    for (let v in extra_inbound) {
        if (v["specify_outbound"] == "1") {
            push(result, {
                type: "field",
                inboundTag: [`extra_inbound_${v[".name"]}`],
                balancerTag: `extra_inbound_outbound_${v[".name"]}`
            });
        }
    }
    return result;
};

export function extra_inbound_global_tcp_tags(extra_inbound) {
    return map(filter(extra_inbound, v => v["specify_outbound"] != "1" && v["inbound_type"] != "tproxy_udp"), v => `extra_inbound_${v[".name"]}`);
};

export function extra_inbound_global_udp_tags(extra_inbound) {
    return map(filter(extra_inbound, v => v["specify_outbound"] != "1" && v["inbound_type"] == "tproxy_udp"), v => `extra_inbound_${v[".name"]}`);
};
