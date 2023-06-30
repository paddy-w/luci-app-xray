"use strict";

import { server_outbound } from "./outbound.mjs";

export function manual_tproxy_outbounds(config, manual_tproxy) {
    let result = [];
    for (let v in manual_tproxy) {
        let tcp_tag = "direct";
        let udp_tag = "direct";
        if (v["force_forward"] == "1") {
            if (v["force_forward_server_tcp"] != null) {
                tcp_tag = `manual_tproxy_outbound_tcp_${v[".name"]}_force_forward_${v["force_forward_server_tcp"]}`;
                const force_forward_server_tcp = config[v["force_forward_server_tcp"]];
                push(result, ...server_outbound(force_forward_server_tcp, tcp_tag, config));
            }
            if (v["force_forward_server_udp"] != null) {
                udp_tag = `manual_tproxy_outbound_udp_${v[".name"]}_force_forward_${v["force_forward_server_udp"]}`;
                const force_forward_server_udp = config[v["force_forward_server_udp"]];
                push(result, ...server_outbound(force_forward_server_udp, udp_tag, config));
            }
        }
        push(result, {
            protocol: "freedom",
            tag: sprintf("manual_tproxy_outbound_tcp_%s", v[".name"]),
            settings: {
                redirect: sprintf("%s:%d", v["dest_addr"] || "", v["dest_port"] || 0),
                domainStrategy: "AsIs"
            },
            proxySettings: {
                tag: tcp_tag
            }
        });
        push(result, {
            protocol: "freedom",
            tag: sprintf("manual_tproxy_outbound_udp_%s", v[".name"]),
            settings: {
                redirect: sprintf("%s:%d", v["dest_addr"] || "", v["dest_port"] || 0),
                domainStrategy: "AsIs"
            },
            proxySettings: {
                tag: udp_tag
            }
        });
    }
    return result;
};

export function manual_tproxy_outbound_tags(manual_tproxy) {
    let result = [];
    for (let v in manual_tproxy) {
        if (v["force_forward"] == "1") {
            push(result, `manual_tproxy_outbound_tcp_${v[".name"]}_force_forward_${v["force_forward_server_tcp"]}`);
            push(result, `manual_tproxy_outbound_udp_${v[".name"]}_force_forward_${v["force_forward_server_udp"]}`);
        }
    }
    return result;
};

export function manual_tproxy_rules(manual_tproxy) {
    let result = [];
    for (let v in manual_tproxy) {
        if (v.sniffing == "1") {
            splice(result, 0, 0, {
                type: "field",
                inboundTag: ["tproxy_tcp_inbound_ms"],
                domain: v["domain_names"],
                port: v["source_port"],
                outboundTag: sprintf("manual_tproxy_outbound_tcp_%s", v[".name"])
            });
            splice(result, 0, 0, {
                type: "field",
                inboundTag: ["tproxy_udp_inbound_ms"],
                domain: v["domain_names"],
                port: v["source_port"],
                outboundTag: sprintf("manual_tproxy_outbound_tcp_%s", v[".name"])
            });
        } else {
            splice(result, 0, 0, {
                type: "field",
                inboundTag: ["tproxy_tcp_inbound", "socks_inbound", "https_inbound", "http_inbound"],
                ip: [v["source_addr"]],
                port: v["source_port"],
                outboundTag: sprintf("manual_tproxy_outbound_tcp_%s", v[".name"])
            });
            splice(result, 0, 0, {
                type: "field",
                inboundTag: ["tproxy_udp_inbound"],
                ip: [v["source_addr"]],
                port: v["source_port"],
                outboundTag: sprintf("manual_tproxy_outbound_udp_%s", v[".name"])
            });
        }
    }
    return result;
};
