'use strict';
'require form';
'require network';
'require uci';
'require view';

const variant = "xray_fw4";

function destination_format(s) {
    const dest = uci.get(variant, s, "destination") || [];
    return dest.map(v => uci.get(variant, v, "alias")).join(", ");
}

function extra_outbound_format(config_data, s, with_desc) {
    const inbound_addr = uci.get(config_data, s, "inbound_addr") || "";
    const inbound_port = uci.get(config_data, s, "inbound_port") || "";
    if (inbound_addr == "" && inbound_port == "") {
        return "-";
    }
    if (with_desc) {
        return `${inbound_addr}:${inbound_port} (${destination_format(s)})`;
    }
    return `${inbound_addr}:${inbound_port}`;
}

return view.extend({
    load: function () {
        return Promise.all([
            uci.load(variant),
            network.getHostHints()
        ]);
    },

    render: function (load_result) {
        const m = new form.Map(variant, _('Xray (preview)'), _("WARNING: These features are experimental, may cause a lot of problems and are not guaranteed to be compatible across minor versions."));
        const config_data = load_result[0];
        const hosts = load_result[1].hosts;

        let s = m.section(form.TypedSection, 'general');
        s.addremove = false;
        s.anonymous = true;

        s.tab('manual_transparent_proxy', _('Manual Transparent Proxy'));

        let tproxy_port_tcp_ms = s.taboption('manual_transparent_proxy', form.Value, 'tproxy_port_tcp_ms', _('Transparent Proxy Port (TCP)'), _("Default TCP entrance for sniffer."));
        tproxy_port_tcp_ms.datatype = 'port';
        tproxy_port_tcp_ms.default = 1084;

        let tproxy_port_udp_ms = s.taboption('manual_transparent_proxy', form.Value, 'tproxy_port_udp_ms', _('Transparent Proxy Port (UDP)'), _("Default UDP entrance for sniffer."));
        tproxy_port_udp_ms.datatype = 'port';
        tproxy_port_udp_ms.default = 1085;

        let ms = s.taboption('manual_transparent_proxy', form.SectionValue, "manual_transparent_proxy_section", form.GridSection, 'manual_tproxy', _('Manual Transparent Proxy'), _('Compared to iptables REDIRECT, Xray could do NAT46 / NAT64 (for example accessing IPv6 only sites). See <a href="https://github.com/v2ray/v2ray-core/issues/2233">FakeDNS</a> for details.')).subsection;
        ms.sortable = false;
        ms.anonymous = true;
        ms.addremove = true;

        let source_addr = ms.option(form.Value, "source_addr", _("Source Address"));
        source_addr.datatype = "ipaddr";
        source_addr.rmempty = true;

        let source_port = ms.option(form.Value, "source_port", _("Source Port"));
        source_port.rmempty = true;

        let sniffing = ms.option(form.Flag, 'sniffing', _('Use sniffing for destination'), _('Enable sniffing for this source address. Do not mix source addresses with different sniffing options.'));
        sniffing.modalonly = true;

        let dest_addr = ms.option(form.Value, "dest_addr", _("Destination Address"));
        dest_addr.depends("sniffing", "0");
        dest_addr.datatype = "host";
        dest_addr.rmempty = true;
        dest_addr.textvalue = function (s) {
            if (uci.get(config_data, s, "sniffing") == "1") {
                return "<i>Sniffing is enabled</i>";
            }
            return uci.get(config_data, s, "dest_addr");
        };

        let dest_port = ms.option(form.Value, "dest_port", _("Destination Port"));
        dest_port.datatype = "port";
        dest_port.rmempty = true;

        let domain_names = ms.option(form.DynamicList, "domain_names", _("Domain names to associate"));
        domain_names.rmempty = true;

        let rebind_domain_ok = ms.option(form.Flag, 'rebind_domain_ok', _('Exempt rebind protection'), _('Avoid dnsmasq filtering RFC1918 IP addresses (and some TESTNET addresses as well) from result.<br/>Must be enabled for TESTNET addresses (<code>192.0.2.0/24</code>, <code>198.51.100.0/24</code>, <code>203.0.113.0/24</code>). Addresses like <a href="https://www.as112.net/">AS112 Project</a> (<code>192.31.196.0/24</code>, <code>192.175.48.0/24</code>) or <a href="https://www.nyiix.net/technical/rtbh/">NYIIX RTBH</a> (<code>198.32.160.7</code>) can avoid that.'));
        rebind_domain_ok.modalonly = true;

        let force_forward = ms.option(form.Flag, 'force_forward', _('Force Forward'), _('This destination must be forwarded through an outbound server.'));
        force_forward.modalonly = true;

        let force_forward_server_tcp = ms.option(form.ListValue, 'force_forward_server_tcp', _('Force Forward server (TCP)'));
        force_forward_server_tcp.depends("force_forward", "1");
        force_forward_server_tcp.datatype = "uciname";
        force_forward_server_tcp.modalonly = true;

        let force_forward_server_udp = ms.option(form.ListValue, 'force_forward_server_udp', _('Force Forward server (UDP)'));
        force_forward_server_udp.depends("force_forward", "1");
        force_forward_server_udp.datatype = "uciname";
        force_forward_server_udp.modalonly = true;

        s.tab("extra_inbounds", "Extra Inbounds");

        let extra_inbounds = s.taboption('extra_inbounds', form.SectionValue, "extra_inbound_section", form.GridSection, 'extra_inbound', _('Extra Inbounds'), _("Add more socks5 / http inbounds and redirect to other outbounds.")).subsection;
        extra_inbounds.sortable = false;
        extra_inbounds.anonymous = true;
        extra_inbounds.addremove = true;
        extra_inbounds.nodescriptions = true;

        let inbound_addr = extra_inbounds.option(form.Value, "inbound_addr", _("Listen Address"));
        inbound_addr.datatype = "ip4addr";
        inbound_addr.rmempty = true;

        let inbound_port = extra_inbounds.option(form.Value, "inbound_port", _("Listen Port"));
        inbound_port.datatype = "port";
        inbound_port.rmempty = true;

        let inbound_type = extra_inbounds.option(form.ListValue, "inbound_type", _("Inbound Type"));
        inbound_type.value("socks5", _("Socks5 Proxy"));
        inbound_type.value("http", _("HTTP Proxy"));
        inbound_type.value("tproxy_tcp", _("Transparent Proxy (TCP)"));
        inbound_type.value("tproxy_udp", _("Transparent Proxy (UDP)"));
        inbound_type.rmempty = false;

        let specify_outbound = extra_inbounds.option(form.Flag, 'specify_outbound', _('Specify Outbound'), _('If not selected, this inbound will use global settings (including sniffing settings). '));
        specify_outbound.modalonly = true;

        let destination = extra_inbounds.option(form.MultiValue, 'destination', _('Destination'), _("Select multiple outbounds for load balancing. If none selected, requests will be sent via direct outbound."));
        destination.depends("specify_outbound", "1");
        destination.datatype = "uciname";
        destination.textvalue = destination_format;

        const servers = uci.sections(config_data, "servers");
        if (servers.length == 0) {
            destination.value("direct", _("No server configured"));
            force_forward_server_tcp.value("direct", _("No server configured"));
            force_forward_server_udp.value("direct", _("No server configured"));

            destination.readonly = true;
            force_forward_server_tcp.readonly = true;
            force_forward_server_udp.readonly = true;
        } else {
            for (const v of uci.sections(config_data, "servers")) {
                destination.value(v[".name"], v.alias || v.server + ":" + v.server_port);
                force_forward_server_tcp.value(v[".name"], v.alias || v.server + ":" + v.server_port);
                force_forward_server_udp.value(v[".name"], v.alias || v.server + ":" + v.server_port);
            }
        }

        s.tab("lan_hosts_access_control", _("LAN Hosts Access Control"));

        let lan_hosts = s.taboption('lan_hosts_access_control', form.SectionValue, "lan_hosts_section", form.GridSection, 'lan_hosts', _('LAN Hosts Access Control'), _("Override global transparent proxy settings here.")).subsection;
        lan_hosts.sortable = false;
        lan_hosts.anonymous = true;
        lan_hosts.addremove = true;

        let macaddr = lan_hosts.option(form.Value, "macaddr", _("MAC Address"));
        macaddr.datatype = "macaddr";
        macaddr.rmempty = false;
        L.sortedKeys(hosts).forEach(function (mac) {
            macaddr.value(mac, E([], [mac, ' (', E('strong', [hosts[mac].name || L.toArray(hosts[mac].ipaddrs || hosts[mac].ipv4)[0] || L.toArray(hosts[mac].ip6addrs || hosts[mac].ipv6)[0] || '?']), ')']));
        });

        let access_control_strategy_v4 = lan_hosts.option(form.ListValue, "access_control_strategy_v4", _("Access Control Strategy (IPv4)"));
        access_control_strategy_v4.value("global", _("Use global settings"));
        access_control_strategy_v4.value("bypass", _("Bypass Xray completely"));
        access_control_strategy_v4.value("forward", _("Forward via extra inbound"));
        access_control_strategy_v4.modalonly = true;
        access_control_strategy_v4.rmempty = false;

        let access_control_forward_tcp_v4 = lan_hosts.option(form.ListValue, "access_control_forward_tcp_v4", _("Extra inbound (TCP4)"));
        access_control_forward_tcp_v4.depends("access_control_strategy_v4", "forward");
        access_control_forward_tcp_v4.rmempty = true;
        access_control_forward_tcp_v4.textvalue = function (s) {
            switch (uci.get(config_data, s, "access_control_strategy_v4")) {
                case "global": {
                    return _("Use Global Settings");
                }
                case "bypass": {
                    return _("Bypass Xray completely");
                }
            }
            return extra_outbound_format(config_data, uci.get(config_data, s, "access_control_forward_tcp_v4"));
        };

        let access_control_forward_udp_v4 = lan_hosts.option(form.ListValue, "access_control_forward_udp_v4", _("Extra inbound (UDP4)"));
        access_control_forward_udp_v4.depends("access_control_strategy_v4", "forward");
        access_control_forward_udp_v4.rmempty = true;
        access_control_forward_udp_v4.textvalue = function (s) {
            switch (uci.get(config_data, s, "access_control_strategy_v4")) {
                case "global": {
                    return _("Use Global Settings");
                }
                case "bypass": {
                    return _("Bypass Xray completely");
                }
            }
            return extra_outbound_format(config_data, uci.get(config_data, s, "access_control_forward_udp_v4"), false);
        };

        let access_control_strategy_v6 = lan_hosts.option(form.ListValue, "access_control_strategy_v6", _("Access Control Strategy (IPv6)"));
        access_control_strategy_v6.value("global", _("Use global settings"));
        access_control_strategy_v6.value("bypass", _("Bypass Xray completely"));
        access_control_strategy_v6.value("forward", _("Forward via extra inbound"));
        access_control_strategy_v6.modalonly = true;
        access_control_strategy_v6.rmempty = false;

        let access_control_forward_tcp_v6 = lan_hosts.option(form.ListValue, "access_control_forward_tcp_v6", _("Extra inbound (TCP6)"));
        access_control_forward_tcp_v6.depends("access_control_strategy_v6", "forward");
        access_control_forward_tcp_v6.rmempty = true;
        access_control_forward_tcp_v6.textvalue = function (s) {
            switch (uci.get(config_data, s, "access_control_strategy_v6")) {
                case "global": {
                    return _("Use Global Settings");
                }
                case "bypass": {
                    return _("Bypass Xray completely");
                }
            }
            return extra_outbound_format(config_data, uci.get(config_data, s, "access_control_forward_tcp_v6"));
        };

        let access_control_forward_udp_v6 = lan_hosts.option(form.ListValue, "access_control_forward_udp_v6", _("Extra inbound (UDP6)"));
        access_control_forward_udp_v6.depends("access_control_strategy_v6", "forward");
        access_control_forward_udp_v6.rmempty = true;
        access_control_forward_udp_v6.textvalue = function (s) {
            switch (uci.get(config_data, s, "access_control_strategy_v6")) {
                case "global": {
                    return _("Use Global Settings");
                }
                case "bypass": {
                    return _("Bypass Xray completely");
                }
            }
            return extra_outbound_format(config_data, uci.get(config_data, s, "access_control_forward_udp_v6"), false);
        };

        for (const v of uci.sections(config_data, "extra_inbound")) {
            switch (v["inbound_type"]) {
                case "tproxy_tcp": {
                    access_control_forward_tcp_v4.value(v[".name"], `${extra_outbound_format(config_data, v[".name"], true)}`);
                    access_control_forward_tcp_v6.value(v[".name"], `${extra_outbound_format(config_data, v[".name"], true)}`);
                    break;
                }
                case "tproxy_udp": {
                    access_control_forward_udp_v4.value(v[".name"], `${extra_outbound_format(config_data, v[".name"], true)}`);
                    access_control_forward_udp_v6.value(v[".name"], `${extra_outbound_format(config_data, v[".name"], true)}`);
                    break;
                }
            }
        }

        return m.render();
    }
});
