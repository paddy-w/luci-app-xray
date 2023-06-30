"use strict";

import { cursor } from "uci";

export function load_config() {
    const uci = cursor();
    uci.load("xray_fw4");
    return uci.get_all("xray_fw4");
};
