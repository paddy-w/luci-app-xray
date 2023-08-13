'use strict';
'require dom';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

const xray_debugvars = rpc.declare({
    object: 'xray',
    method: 'debugvars',
    params: [],
    expect: { '': {} }
});

function greater_than_zero(n) {
    if (n < 0) {
        return 0;
    }
    return n;
}

function get_inbound_uci_description(config, key) {
    switch (key) {
        case "https_inbound": {
            return `${key} [https://0.0.0.0:443]`;
        }
        case "http_inbound": {
            return `${key} [http://0.0.0.0:${uci.get_first(config, "general", "http_port") || 1083}]`;
        }
        case "socks_inbound": {
            return `${key} [socks5://0.0.0.0:${uci.get_first(config, "general", "socks_port") || 1082}]`;
        }
        case "tproxy_tcp_inbound": {
            return `${key} [tproxy_tcp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_tcp") || 1080}]`;
        }
        case "tproxy_udp_inbound": {
            return `${key} [tproxy_udp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_udp") || 1081}]`;
        }
        case "tproxy_tcp_inbound_v6": {
            return `${key} [tproxy_tcp://[::]:${uci.get_first(config, "general", "tproxy_port_tcp_v6") || 1084}]`;
        }
        case "tproxy_udp_inbound_v6": {
            return `${key} [tproxy_udp://[::]:${uci.get_first(config, "general", "tproxy_port_udp_v6") || 1085}]`;
        }
        case "tproxy_tcp_inbound_ms": {
            return `${key} [tproxy_tcp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_tcp_ms") || 1088}]`;
        }
        case "tproxy_udp_inbound_ms": {
            return `${key} [tproxy_udp://0.0.0.0:${uci.get_first(config, "general", "tproxy_port_udp_ms") || 1089}]`;
        }
    }
    const uci_key = key.slice(-9);
    const uci_item = uci.get(config, uci_key);
    if (uci_item == null) {
        return key;
    }
    switch (uci_item[".type"]) {
        case "extra_inbound": {
            return `${key} [${uci_item["inbound_type"]}://${uci_item["inbound_addr"]}:${uci_item["inbound_port"]}]`;
        }
    }
    return key;
}

function outbound_format(server) {
    if (server["alias"]) {
        return server["alias"];
    }
    if (server["server"].includes(":")) {
        return `${server["transport"]},[${server["server"]}]:${server["server_port"]}`;
    }
    return `${server["transport"]},${server["server"]}:${server["server_port"]}`;
}

function get_outbound_uci_description(config, key) {
    const uci_key = key.slice(-9);
    const uci_item = uci.get(config, uci_key);
    if (uci_item == null) {
        return key;
    }
    switch (uci_item[".type"]) {
        case "servers": {
            return `${key} [${outbound_format(uci_item)}]`;
        }
        case "extra_inbound": {
            const proxy_value = uci_item["destination"];
            return `${key} @ ${get_outbound_uci_description(config, proxy_value)}`;
        }
        case "manual_tproxy": {
            const dest_addr = uci_item["dest_addr"] || "{sniffing}";
            if (uci_item["force_forward"] == '1') {
                return `${key} [${uci_item["source_addr"]}:${uci_item["source_port"]} -> ${dest_addr}:${uci_item["dest_port"]}] (see force_forward below)`;
            }
            return `${key} [${uci_item["source_addr"]}:${uci_item["source_port"]} -> ${dest_addr}:${uci_item["dest_port"]}]`;
        }
    }
    return key;
}

function get_dns_cache_by_server(key, value) {
    return [
        E('h4', key),
        E('table', { 'class': 'table' }, [
            E('tr', { 'class': 'tr table-titles' }, [
                E('th', { 'class': 'th' }, _('Domain Name')),
                E('th', { 'class': 'th' }, _('Values')),
            ]),
            ...Object.entries(value).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                E('td', { 'class': 'td' }, v[0]),
                E('td', { 'class': 'td' }, v[1].join(", ")),
            ]))
        ])
    ];
}

function get_dns_cache(vars) {
    const dns_cache = Object.entries(vars["dns_cache"]);
    let result = [];
    for (const i of dns_cache) {
        for (const j of get_dns_cache_by_server(i[0], i[1])) {
            result.push(j);
        }
    }
    return result;
}

return view.extend({
    load: function () {
        return uci.load("xray_fw4");
    },

    render: function (config) {
        if (uci.get_first(config, "general", "metrics_server_enable") != "1") {
            return E([], [
                E('h2', _('Xray (status)')),
                E('p', { 'class': 'cbi-map-descr' }, _("Xray metrics server not enabled. Enable Xray metrics server to see statistics."))
            ]);
        }
        const info = E('p', { 'class': 'cbi-map-descr' }, _("Collecting data. If any error occurs, check if ucode-mod-http is installed correctly."));
        const detail = E('div', {});
        poll.add(function () {
            xray_debugvars().then(function (load_result) {
                const now_timestamp = new Date().getTime() / 1000;
                const vars = load_result["json"];
                const core = vars["core"];
                const aesgcm = function () {
                    if (core["system"]["aesgcm"]) {
                        return _("Supported");
                    }
                    return _("Not supported");
                };

                const core_table = E('table', { 'class': 'table' }, [
                    E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                        E('td', { 'class': 'td', 'width': '40%' }, _("Version")),
                        E('td', { 'class': 'td' }, `${vars["version"]["version"]} (${vars["version"]["version_statement"][0].split(" ")[5]})`),
                    ]),
                    E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                        E('td', { 'class': 'td', 'width': '40%' }, _('Total CPU Cores')),
                        E('td', { 'class': 'td' }, core["system"]["numcpu"]),
                    ]),
                    E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                        E('td', { 'class': 'td', 'width': '40%' }, _('Hardware AES-GCM acceleration')),
                        E('td', { 'class': 'td' }, aesgcm()),
                    ]),
                    E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                        E('td', { 'class': 'td', 'width': '40%' }, _('Random TLS Fingerprint')),
                        E('td', { 'class': 'td' }, `${vars["random_tls_fingerprint"]["client"]} ${vars["random_tls_fingerprint"]["version"]}`),
                    ]),
                    E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                        E('td', { 'class': 'td', 'width': '40%' }, _('Uptime')),
                        E('td', { 'class': 'td' }, '%t'.format(core["runtime"]["uptime"])),
                    ]),
                    E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                        E('td', { 'class': 'td', 'width': '40%' }, _('Goroutines')),
                        E('td', { 'class': 'td' }, `${core["runtime"]["numgos"]}`),
                    ]),
                    E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
                        E('td', { 'class': 'td', 'width': '40%' }, _('Memory Stats')),
                        E('td', { 'class': 'td' }, 'Alloc: %.2mB; HeapSys: %.2mB; StackSys: %.2mB; GC: %d (%d Forced)'.format(vars["memstats"]["Alloc"], vars["memstats"]["HeapSys"], vars["memstats"]["StackSys"], vars["memstats"]["NumGC"], vars["memstats"]["NumForcedGC"])),
                    ]),
                ]);

                const observatory = E('table', { 'class': 'table' }, [
                    E('tr', { 'class': 'tr table-titles' }, [
                        E('th', { 'class': 'th' }, _('Tag')),
                        E('th', { 'class': 'th' }, _('Latency')),
                        E('th', { 'class': 'th' }, _('Last seen')),
                        E('th', { 'class': 'th' }, _('Last check')),
                    ]), ...Object.entries(vars["observatory"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                        E('td', { 'class': 'td' }, get_outbound_uci_description(config, v[0])),
                        E('td', { 'class': 'td' }, function (c) {
                            if (c[1]["alive"]) {
                                return c[1]["delay"] + ' ' + _("ms");
                            }
                            return "<i>unreachable</i>";
                        }(v)),
                        E('td', { 'class': 'td' }, '%d'.format(greater_than_zero(now_timestamp - v[1]["last_seen_time"])) + _('s ago')),
                        E('td', { 'class': 'td' }, '%d'.format(greater_than_zero(now_timestamp - v[1]["last_try_time"])) + _('s ago')),
                    ]))
                ]);

                const all_balancer_outbounds = {};
                Object.entries(vars["stats"]["balancer"]).forEach(function (v1, i1, a1) {
                    Object.entries(v1[1]).forEach(function (v2, i2, a2) {
                        all_balancer_outbounds[v2[0].slice(-9)] = true;
                    });
                });

                const balancer_stats = E('table', { 'class': 'table' }, [
                    E('tr', { 'class': 'tr table-titles' }, [
                        E('th', { 'class': 'th' }, _('Outbound / Balancer')),
                        ...Object.keys(vars["stats"]["balancer"]).map((v, index, arr) => E('th', { 'class': 'th' }, v))
                    ]), ...Object.keys(all_balancer_outbounds).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                        E('td', { 'class': 'td' }, get_outbound_uci_description(config, v)),
                        ...Object.entries(vars["stats"]["balancer"]).map(function (v2, i2, a2) {
                            for (const o in v2[1]) {
                                if (v == o.slice(-9)) {
                                    return E('td', { 'class': 'td' }, v2[1][o]);
                                }
                            }
                            return E('td', { 'class': 'td' }, "-");
                        })
                    ]))
                ]);

                const outbound_stats = E('table', { 'class': 'table' }, [
                    E('tr', { 'class': 'tr table-titles' }, [
                        E('th', { 'class': 'th' }, _('Tag')),
                        E('th', { 'class': 'th' }, _('Downlink')),
                        E('th', { 'class': 'th' }, _('Uplink')),
                    ]), ...Object.entries(vars["stats"]["outbound"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                        E('td', { 'class': 'td' }, get_outbound_uci_description(config, v[0])),
                        E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["downlink"])),
                        E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["uplink"])),
                    ]))
                ]);

                const inbound_stats = E('table', { 'class': 'table' }, [
                    E('tr', { 'class': 'tr table-titles' }, [
                        E('th', { 'class': 'th' }, _('Tag')),
                        E('th', { 'class': 'th' }, _('Downlink')),
                        E('th', { 'class': 'th' }, _('Uplink')),
                    ]), ...Object.entries(vars["stats"]["inbound"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                        E('td', { 'class': 'td' }, get_inbound_uci_description(config, v[0])),
                        E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["downlink"])),
                        E('td', { 'class': 'td' }, '%.2mB'.format(v[1]["uplink"])),
                    ]))
                ]);

                const dns_server = E('table', { 'class': 'table' }, [
                    E('tr', { 'class': 'tr table-titles' }, [
                        E('th', { 'class': 'th' }, _('Server')),
                        E('th', { 'class': 'th' }, _('Cache size')),
                        E('th', { 'class': 'th' }, _('Cache alloc')),
                        E('th', { 'class': 'th' }, _('Cache flush')),
                        E('th', { 'class': 'th' }, _('Cache hits')),
                        E('th', { 'class': 'th' }, _('Cache misses')),
                        E('th', { 'class': 'th' }, _('Cache expire')),
                        E('th', { 'class': 'th' }, _('Query success')),
                        E('th', { 'class': 'th' }, _('Query failure')),
                        E('th', { 'class': 'th' }, _('Query timeout')),
                    ]), ...Object.entries(vars["stats"]["dns"]).map((v, index, arr) => E('tr', { 'class': `tr cbi-rowstyle-${index % 2 + 1}` }, [
                        E('td', { 'class': 'td' }, v[0]),
                        E('td', { 'class': 'td' }, v[1]["cache_size"] || 0),
                        E('td', { 'class': 'td' }, v[1]["cache_alloc"] || 0),
                        E('td', { 'class': 'td' }, v[1]["cache_flush"] || 0),
                        E('td', { 'class': 'td' }, v[1]["cache_hits"] || 0),
                        E('td', { 'class': 'td' }, v[1]["cache_misses"] || 0),
                        E('td', { 'class': 'td' }, v[1]["cache_expire"] || 0),
                        E('td', { 'class': 'td' }, v[1]["query_success"] || 0),
                        E('td', { 'class': 'td' }, v[1]["query_failure"] || 0),
                        E('td', { 'class': 'td' }, v[1]["query_timeout"] || 0),
                    ]))
                ]);

                const result = E([], [
                    E('div', {}, [
                        E('div', { 'class': 'cbi-section', 'data-tab': 'observatory', 'data-tab-title': _('Observatory') }, [
                            E('h3', _('Core Information')),
                            E('div', { 'class': 'cbi-map-descr' }, _("Basic information about system and Xray runtime.")),
                            core_table,

                            E('h3', _('Outbound Observatory')),
                            E('div', { 'class': 'cbi-map-descr' }, "Availability of outbound servers are probed every few seconds."),
                            observatory,
                        ]),
                        E('div', { 'class': 'cbi-section', 'data-tab': 'statistics', 'data-tab-title': _('Statistics') }, [
                            E('h3', _('Outbound Statistics')),
                            E('div', { 'class': 'cbi-map-descr' }, "Data transferred for outbounds since Xray start."),
                            outbound_stats,

                            E('h3', _('Balancer Statistics')),
                            E('div', { 'class': 'cbi-map-descr' }, "Outbound picks by balancers."),
                            balancer_stats,

                            E('h3', _('Inbound Statistics')),
                            E('div', { 'class': 'cbi-map-descr' }, "Data transferred for inbounds since Xray start."),
                            inbound_stats,
                        ]),
                        E('div', { 'class': 'cbi-section', 'data-tab': 'dns', 'data-tab-title': _('DNS') }, [
                            E('h3', _('DNS Server and Cache Information')),
                            E('div', { 'class': 'cbi-map-descr' }, "Xray Local DNS server statistics (queries and cache details)."),
                            dns_server,
                            ...get_dns_cache(vars),
                        ]),
                    ])
                ]);
                ui.tabs.initTabGroup(result.lastElementChild.childNodes);
                dom.content(info, vars["version"]["version_statement"][0]);
                dom.content(detail, result);
            });
        });


        return E([], [
            E('h2', _('Xray (status)')),
            info,
            detail
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
