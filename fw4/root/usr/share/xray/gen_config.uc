#!/usr/bin/ucode
"use strict";

import { lsdir } from "fs";
import { load_config } from "./common/config.mjs";
import { balancer, api_conf, metrics_conf, logging, policy, system_route_rules } from "./feature/system.mjs";
import { blocked_domain_rules, fast_domain_rules, secure_domain_rules, dns_server_tags, dns_server_inbounds, dns_server_outbound, dns_conf } from "./feature/dns.mjs";
import { socks_inbound, http_inbound, https_inbound, dokodemo_inbound } from "./feature/inbound.mjs";
import { blackhole_outbound, direct_outbound, server_outbound } from "./feature/outbound.mjs";
import { bridges, bridge_outbounds, bridge_rules } from "./feature/bridge.mjs";
import { extra_inbounds, extra_inbound_rules, extra_inbound_global_tcp_tags, extra_inbound_global_udp_tags } from "./feature/extra_inbound.mjs";
import { manual_tproxy_outbounds, manual_tproxy_outbound_tags, manual_tproxy_rules } from "./feature/manual_tproxy.mjs";

const config = load_config();
const proxy = config[filter(keys(config), k => config[k][".type"] == "general")[0]];
const bridge = map(filter(keys(config), k => config[k][".type"] == "bridge") || [], k => config[k]);
const manual_tproxy = map(filter(keys(config), k => config[k][".type"] == "manual_tproxy") || [], k => config[k]);
const extra_inbound = map(filter(keys(config), k => config[k][".type"] == "extra_inbound") || [], k => config[k]);

const share_dir = lsdir("/usr/share/xray");
const geoip_existence = index(share_dir, "geoip.dat") > 0;

function inbounds() {
    let i = [
        dokodemo_inbound("0.0.0.0", proxy["tproxy_port_tcp"] || 1080, "tproxy_tcp_inbound", proxy["tproxy_sniffing"], proxy["route_only"], ["http", "tls"], "tcp", "tproxy"),
        dokodemo_inbound("0.0.0.0", proxy["tproxy_port_udp"] || 1081, "tproxy_udp_inbound", proxy["tproxy_sniffing"], proxy["route_only"], ["quic"], "udp", "tproxy"),
        dokodemo_inbound("0.0.0.0", proxy["tproxy_port_tcp_v6"] || 1084, "tproxy_tcp_inbound_v6", proxy["tproxy_sniffing"], proxy["route_only"], ["http", "tls"], "tcp", "tproxy"),
        dokodemo_inbound("0.0.0.0", proxy["tproxy_port_udp_v6"] || 1085, "tproxy_udp_inbound_v6", proxy["tproxy_sniffing"], proxy["route_only"], ["quic"], "udp", "tproxy"),
        socks_inbound("0.0.0.0", proxy["socks_port"] || 1082, "socks_inbound"),
        http_inbound("0.0.0.0", proxy["http_port"] || 1083, "http_inbound"),
        dokodemo_inbound("0.0.0.0", proxy["tproxy_port_tcp_ms"] || 1088, "tproxy_tcp_inbound_ms", "1", "0", ["http", "tls"], "tcp", "tproxy"),
        dokodemo_inbound("0.0.0.0", proxy["tproxy_port_udp_ms"] || 1089, "tproxy_udp_inbound_ms", "1", "0", ["quic"], "udp", "tproxy"),
        ...dns_server_inbounds(proxy),
        ...extra_inbounds(proxy, extra_inbound),
    ];
    if (proxy["web_server_enable"] == "1") {
        push(i, https_inbound(proxy, config));
    }
    if (proxy["metrics_server_enable"] == '1') {
        push(i, {
            listen: "0.0.0.0",
            port: int(proxy["metrics_server_port"]) || 18888,
            protocol: "dokodemo-door",
            settings: {
                address: "127.0.0.1"
            },
            tag: "metrics"
        });
    }
    if (proxy["xray_api"] == '1') {
        push(i, {
            listen: "127.0.0.1",
            port: 8080,
            protocol: "dokodemo-door",
            settings: {
                address: "127.0.0.1"
            },
            tag: "api"
        });
    }
    return i;
}

function outbounds() {
    let result = [
        direct_outbound("direct"),
        blackhole_outbound(),
        dns_server_outbound(),
        ...manual_tproxy_outbounds(config, manual_tproxy),
        ...bridge_outbounds(config, bridge)
    ];
    let outbound_balancers_all = {};
    for (let i in balancer(proxy, "tcp_balancer", "tcp_balancer")) {
        if (i != "direct") {
            outbound_balancers_all[i] = true;
        }
    }
    for (let i in balancer(proxy, "udp_balancer", "udp_balancer")) {
        if (i != "direct") {
            outbound_balancers_all[i] = true;
        }
    }
    for (let i in balancer(proxy, "tcp_balancer_v6", "tcp_balancer_v6")) {
        if (i != "direct") {
            outbound_balancers_all[i] = true;
        }
    }
    for (let i in balancer(proxy, "udp_balancer_v6", "udp_balancer_v6")) {
        if (i != "direct") {
            outbound_balancers_all[i] = true;
        }
    }
    for (let e in extra_inbound) {
        if (e["specify_outbound"] == "1") {
            for (let i in balancer(e, "destination", `extra_inbound_${e[".name"]}`)) {
                if (i != "direct") {
                    outbound_balancers_all[i] = true;
                }
            }
        }
    }
    for (let i in keys(outbound_balancers_all)) {
        push(result, ...server_outbound(config[substr(i, -9)], i, config));
    }
    return result;
}

function rules() {
    const tproxy_tcp_inbound_tags = ["tproxy_tcp_inbound"];
    const tproxy_udp_inbound_tags = ["tproxy_udp_inbound"];
    const tproxy_tcp_inbound_v6_tags = ["tproxy_tcp_inbound_v6"];
    const tproxy_udp_inbound_v6_tags = ["tproxy_udp_inbound_v6"];
    const built_in_tcp_inbounds = [...tproxy_tcp_inbound_tags, "socks_inbound", "https_inbound", "http_inbound"];
    const built_in_udp_inbounds = [...tproxy_udp_inbound_tags, "dns_conf_inbound"];
    const extra_inbound_global_tcp = extra_inbound_global_tcp_tags() || [];
    const extra_inbound_global_udp = extra_inbound_global_udp_tags() || [];
    let result = [
        ...manual_tproxy_rules(manual_tproxy),
        ...extra_inbound_rules(extra_inbound),
        ...system_route_rules(proxy),
        ...bridge_rules(bridge),
        ...function () {
            let direct_rules = [];
            if (geoip_existence) {
                if (proxy["geoip_direct_code_list"] != null) {
                    const geoip_direct_code_list = map(proxy["geoip_direct_code_list"] || [], v => "geoip:" + v);
                    if (length(geoip_direct_code_list) > 0) {
                        push(direct_rules, {
                            type: "field",
                            inboundTag: [...built_in_tcp_inbounds, ...built_in_udp_inbounds, ...extra_inbound_global_tcp, ...extra_inbound_global_udp],
                            outboundTag: "direct",
                            ip: geoip_direct_code_list
                        });
                    }
                    const geoip_direct_code_list_v6 = map(proxy["geoip_direct_code_list_v6"] || [], v => "geoip:" + v);
                    if (length(geoip_direct_code_list_v6) > 0) {
                        push(direct_rules, {
                            type: "field",
                            inboundTag: [...tproxy_tcp_inbound_v6_tags, ...tproxy_udp_inbound_v6_tags],
                            outboundTag: "direct",
                            ip: geoip_direct_code_list_v6
                        });
                    }
                }
                push(direct_rules, {
                    type: "field",
                    inboundTag: [...tproxy_tcp_inbound_v6_tags, ...tproxy_udp_inbound_v6_tags, ...built_in_tcp_inbounds, ...built_in_udp_inbounds, ...extra_inbound_global_tcp, ...extra_inbound_global_udp],
                    outboundTag: "direct",
                    ip: ["geoip:private"]
                });
            }
            return direct_rules;
        }(),
        {
            type: "field",
            inboundTag: [...tproxy_tcp_inbound_v6_tags],
            balancerTag: "tcp_outbound_v6"
        },
        {
            type: "field",
            inboundTag: [...tproxy_udp_inbound_v6_tags],
            balancerTag: "udp_outbound_v6"
        },
        {
            type: "field",
            inboundTag: [...built_in_tcp_inbounds, ...extra_inbound_global_tcp],
            balancerTag: "tcp_outbound"
        },
        {
            type: "field",
            inboundTag: [...built_in_udp_inbounds, ...extra_inbound_global_udp],
            balancerTag: "udp_outbound"
        },
        {
            type: "field",
            inboundTag: dns_server_tags(proxy),
            outboundTag: "dns_server_outbound"
        },
    ];
    if (proxy["tproxy_sniffing"] == "1") {
        if (length(secure_domain_rules(proxy)) > 0) {
            splice(result, 0, 0, {
                type: "field",
                inboundTag: [...tproxy_udp_inbound_tags, ...extra_inbound_global_udp],
                balancerTag: "udp_outbound",
                domain: secure_domain_rules(proxy),
            });
            splice(result, 0, 0, {
                type: "field",
                inboundTag: [...tproxy_tcp_inbound_tags, ...extra_inbound_global_tcp],
                balancerTag: "tcp_outbound",
                domain: secure_domain_rules(proxy),
            });
        }
        if (length(blocked_domain_rules(proxy)) > 0) {
            splice(result, 0, 0, {
                type: "field",
                inboundTag: [...tproxy_tcp_inbound_tags, ...tproxy_tcp_inbound_tags, ...extra_inbound_global_tcp, ...extra_inbound_global_udp],
                outboundTag: "blackhole_outbound",
                domain: blocked_domain_rules(proxy),
            });
        }
        splice(result, 0, 0, {
            type: "field",
            inboundTag: [...tproxy_tcp_inbound_tags, ...tproxy_tcp_inbound_tags, ...extra_inbound_global_tcp, ...extra_inbound_global_udp],
            outboundTag: "direct",
            domain: fast_domain_rules(proxy)
        });
        if (proxy["direct_bittorrent"] == "1") {
            splice(result, 0, 0, {
                type: "field",
                outboundTag: "direct",
                protocol: ["bittorrent"]
            });
        }
    }
    return result;
}

function balancers() {
    let result = [
        {
            "tag": "tcp_outbound",
            "selector": balancer(proxy, "tcp_balancer", "tcp_balancer"),
            "strategy": {
                "type": "random"
            }
        },
        {
            "tag": "udp_outbound",
            "selector": balancer(proxy, "udp_balancer", "udp_balancer"),
            "strategy": {
                "type": "random"
            }
        },
        {
            "tag": "tcp_outbound_v6",
            "selector": balancer(proxy, "tcp_balancer_v6", "tcp_balancer_v6"),
            "strategy": {
                "type": "random"
            }
        },
        {
            "tag": "udp_outbound_v6",
            "selector": balancer(proxy, "udp_balancer_v6", "udp_balancer_v6"),
            "strategy": {
                "type": "random"
            }
        }
    ];
    for (let e in extra_inbound) {
        if (e["specify_outbound"] == "1") {
            push(result, {
                "tag": `extra_inbound_outbound_${e[".name"]}`,
                "selector": balancer(e, "destination", `extra_inbound_${e[".name"]}`),
                "strategy": {
                    "type": "random"
                }
            });
        }
    }
    return result;
};

function observatory() {
    if (proxy["observatory"] == "1") {
        return {
            subjectSelector: ["tcp_balancer_outbound", "udp_balancer_outbound", "tcp_balancer_v6_outbound", "udp_balancer_v6_outbound", "extra_inbound", "direct", ...manual_tproxy_outbound_tags(manual_tproxy)],
            probeInterval: "100ms",
            probeUrl: "http://www.apple.com/library/test/success.html"
        };
    }
    return null;
}

function gen_config() {
    return {
        inbounds: inbounds(),
        outbounds: outbounds(),
        dns: dns_conf(proxy, config, manual_tproxy),
        api: api_conf(proxy),
        metrics: metrics_conf(proxy),
        policy: policy(proxy),
        log: logging(proxy),
        stats: proxy["stats"] == "1" ? {
            place: "holder"
        } : null,
        observatory: observatory(),
        reverse: {
            bridges: bridges(bridge)
        },
        routing: {
            domainStrategy: proxy["routing_domain_strategy"] || "AsIs",
            rules: rules(),
            balancers: balancers(proxy, extra_inbound)
        }
    };
}

print(gen_config());
