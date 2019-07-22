
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 27JUNI2019
 * By @guntur.wj
 *
 * Adding And Editing
 * By @rokhman.syamsudin
 */

package com.solusi247.labs.parser.firewall;

import com.google.common.collect.ImmutableMap;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.lang.invoke.MethodHandles;
import java.time.Clock;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import oi.thekraken.grok.api.Grok;
import oi.thekraken.grok.api.Match;
import oi.thekraken.grok.api.exception.GrokException;
import org.apache.metron.common.Constants;
import org.apache.metron.parsers.BasicParser;
import org.apache.metron.parsers.ParseException;
import org.apache.metron.parsers.utils.SyslogUtils;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BasicCustomFirewallParser extends BasicParser {
    protected static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    protected Clock deviceClock;
    private String syslogPattern = "%{CISCO_TAGGED_SYSLOG}";

    // Custom Properties
    private String firewallDevicePattern = "%{FIREWALL_DEVICE}";
    private String f5FirewallPattern = "%{F5_FIREWALL}";

    private Grok generalFirewallGrok;

    private static final Map<String, String> patternMap = ImmutableMap.<String, String>builder()
            .put("ASA-4-722041", "CISCOFW722041")
            .put("ASA-2-106001", "CISCOFW106001")
            .put("ASA-2-106006", "CISCOFW106006_106007_106010")
            .put("ASA-2-106007", "CISCOFW106006_106007_106010")
            .put("ASA-2-106010", "CISCOFW106006_106007_106010")
            .put("ASA-3-106014", "CISCOFW106014")
            .put("ASA-6-106015", "CISCOFW106015")
            .put("ASA-1-106021", "CISCOFW106021")
            .put("ASA-4-106023", "CISCOFW106023")
            .put("ASA-5-106100", "CISCOFW106100")
            .put("ASA-6-110002", "CISCOFW110002")
            .put("ASA-6-302010", "CISCOFW302010")
            .put("ASA-6-302013", "CISCOFW302013_302014_302015_302016")
            .put("ASA-6-302014", "CISCOFW302013_302014_302015_302016")
            .put("ASA-6-302015", "CISCOFW302013_302014_302015_302016")
            .put("ASA-6-302016", "CISCOFW302013_302014_302015_302016")
            .put("ASA-6-302020", "CISCOFW302020_302021")
            .put("ASA-6-302021", "CISCOFW302020_302021")
            .put("ASA-6-305011", "CISCOFW305011")
            .put("ASA-3-313001", "CISCOFW313001_313004_313008")
            .put("ASA-3-313004", "CISCOFW313001_313004_313008")
            .put("ASA-3-313008", "CISCOFW313001_313004_313008")
            .put("ASA-4-313005", "CISCOFW313005")
            .put("ASA-4-402117", "CISCOFW402117")
            .put("ASA-4-402119", "CISCOFW402119")
            .put("ASA-4-419001", "CISCOFW419001")
            .put("ASA-4-419002", "CISCOFW419002")
            .put("ASA-4-500004", "CISCOFW500004")
            .put("ASA-6-602303", "CISCOFW602303_602304")
            .put("ASA-6-602304", "CISCOFW602303_602304")
            .put("ASA-7-710001", "CISCOFW710001_710002_710003_710005_710006")
            .put("ASA-7-710002", "CISCOFW710001_710002_710003_710005_710006")
            .put("ASA-7-710003", "CISCOFW710001_710002_710003_710005_710006")
            .put("ASA-7-710005", "CISCOFW710001_710002_710003_710005_710006")
            .put("ASA-7-710006", "CISCOFW710001_710002_710003_710005_710006")
            .put("ASA-6-713172", "CISCOFW713172")
            .put("ASA-4-733100", "CISCOFW733100")
            .put("ASA-6-305012", "CISCOFW305012")
            .put("ASA-7-609001", "CISCOFW609001")
            .put("ASA-7-609002", "CISCOFW609002")
            .put("ASA-5-713041", "CISCOFW713041")
            .put("ASA-6-716002", "CISCOFW716002")
            .put("cisco", "CISCO_TAGGED_SYSLOG")
            .put("f5", "F5_FIREWALL")
            .build();

    private Map<String, Grok> grokers = new HashMap<String, Grok>(patternMap.size());

    @Override
    public void configure(Map<String, Object> parserConfig) {
        String timeZone = (String) parserConfig.get("deviceTimeZone");
        if (timeZone != null)
            deviceClock = Clock.system(ZoneId.of(timeZone));
        else {
            deviceClock = Clock.systemUTC();
            LOG.warn("[Metron] No device time zone provided; defaulting to UTC");
        }
    }

    private void addGrok(String key, String pattern) throws GrokException {
        Grok grok = new Grok();
        InputStream patternStream = this.getClass().getResourceAsStream("/patterns/firewall");
        grok.addPatternFromReader(new InputStreamReader(patternStream));
        grok.compile("%{" + pattern + "}");
        grokers.put(key, grok);
    }

    @Override
    public void init() {
        generalFirewallGrok = new Grok();
        InputStream syslogStream = this.getClass().getResourceAsStream("/patterns/firewall");
        try {
            generalFirewallGrok.addPatternFromReader(new InputStreamReader(syslogStream));

            generalFirewallGrok.compile(firewallDevicePattern);
        } catch (GrokException e) {
            LOG.error("[Labs247] Failed to load grok patterns from jar", e);
            throw new RuntimeException(e.getMessage(), e);
        }

        for (Entry<String, String> pattern : patternMap.entrySet()) {
            try {
                addGrok(pattern.getKey(), pattern.getValue());
            } catch (GrokException e) {
                LOG.error("[Metron] Failed to load grok pattern {} for ASA tag {}", pattern.getValue(), pattern.getKey());
            }
        }

        LOG.info("[Metron] CISCO ASA Parser Initialized");
    }

    @Override
    public List<JSONObject> parse(byte[] rawMessage) {
        String logLine = "";
        String firewallMessagePattern = "";
        JSONObject metronJson = new JSONObject();
        List<JSONObject> messages = new ArrayList<>();
        Map<String, Object> firewallJson = new HashMap<String, Object>();

        try {
            logLine = new String(rawMessage, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            LOG.error("[Metron] Could not read raw message", e);
            throw new RuntimeException(e.getMessage(), e);
        }

        try {
            LOG.debug("[Metron] Started parsing raw message: {}", logLine);

            Match generalMatch = generalFirewallGrok.match(logLine);
            generalMatch.captures();
            if (!generalMatch.isNull()) {
                firewallJson = generalMatch.toMap();
                LOG.trace("[Labs247] Grok Device Firewall matches: {}", generalMatch.toJson());

                metronJson.put(Constants.Fields.ORIGINAL.getName(), logLine);

                String dvc_fw_type = firewallJson.get("dvc_fw_type").toString().toLowerCase();
                metronJson.put("device_fw_type", dvc_fw_type);

                firewallMessagePattern = (String) firewallJson.get("fw_msg");
                LOG.debug("[Labs247] parse firewall message : {}", firewallMessagePattern);
                JSONObject resultParse;

                if(dvc_fw_type.equals("f5")){
                    resultParse = parseF5(firewallMessagePattern);

                    if(!resultParse.isEmpty())
                        metronJson.putAll(parseF5(firewallMessagePattern));
                }

                if(dvc_fw_type.equals("cisco")) {
                    resultParse = parseCisco(firewallMessagePattern);

                    if(!resultParse.isEmpty()) {
                        metronJson.putAll(parseCisco(firewallMessagePattern));
                    }
                }

            } else
                throw new RuntimeException(
                        String.format("[Metron] Message '%s' does not match pattern '%s'", logLine, firewallDevicePattern));
        } catch (RuntimeException e) {
            LOG.error(e.getMessage(), e);
            throw new RuntimeException(e.getMessage(), e);
        }

        messages.add(metronJson);
        return messages;
    }


    private JSONObject parseCisco(String toParse) {
        JSONObject toReturnCisco = new JSONObject();

        String messagePattern = "";
        Map<String, Object> syslogJson = new HashMap<String, Object>();

        LOG.debug("[Metron] Started parsing Cisco raw message: {}", toParse);
        Grok syslogGrok = grokers.get("cisco");

        Match syslogMatch = syslogGrok.match(toParse);
        syslogMatch.captures();
        if (!syslogMatch.isNull()) {
            syslogJson = syslogMatch.toMap();
            LOG.debug("[Metron] Grok CISCO ASA syslog matches: {}", syslogMatch.toJson());

            try {
                toReturnCisco.put(Constants.Fields.TIMESTAMP.getName(),
                        SyslogUtils.parseTimestampToEpochMillis((String) syslogJson.get("CISCOTIMESTAMP"), deviceClock));
            } catch (ParseException e) {
                e.printStackTrace();
            }

            toReturnCisco.put("ciscotag", syslogJson.get("CISCOTAG"));
            toReturnCisco.put("syslog_severity", SyslogUtils.getSeverityFromPriority((int) syslogJson.get("syslog_pri")));
            toReturnCisco.put("syslog_facility", SyslogUtils.getFacilityFromPriority((int) syslogJson.get("syslog_pri")));

            if (syslogJson.get("syslog_host") != null) {
                toReturnCisco.put("syslog_host", syslogJson.get("syslog_host"));
            }
            if (syslogJson.get("syslog_prog") != null) {
                toReturnCisco.put("syslog_prog", syslogJson.get("syslog_prog"));
            }

        } else
            throw new RuntimeException(
                    String.format("[Metron] Message '%s' does not match pattern '%s'", toParse, syslogPattern));

        messagePattern = (String) syslogJson.get("CISCOTAG");
        LOG.debug("[Labs247] messagePattern is : {}", toParse);
        Grok asaGrok = grokers.get(messagePattern);

        if (asaGrok == null)
            LOG.info("[Metron] No pattern for ciscotag '{}'", syslogJson.get("CISCOTAG"));
        else {

            String messageContent = (String) syslogJson.get("message");
            Match messageMatch = asaGrok.match(messageContent);
            messageMatch.captures();
            if (!messageMatch.isNull()) {
                Map<String, Object> messageJson = messageMatch.toMap();
                LOG.trace("[Metron] Grok CISCO ASA message matches: {}", messageMatch.toJson());

                String src_ip = (String) messageJson.get("src_ip");
                if (src_ip != null)
                    toReturnCisco.put(Constants.Fields.SRC_ADDR.getName(), src_ip);

                Integer src_port = (Integer) messageJson.get("src_port");
                if (src_port != null)
                    toReturnCisco.put(Constants.Fields.SRC_PORT.getName(), src_port);

                String dst_ip = (String) messageJson.get("dst_ip");
                if (dst_ip != null)
                    toReturnCisco.put(Constants.Fields.DST_ADDR.getName(), dst_ip);

                Integer dst_port = (Integer) messageJson.get("dst_port");
                if (dst_port != null)
                    toReturnCisco.put(Constants.Fields.DST_PORT.getName(), dst_port);

                String protocol = (String) messageJson.get("protocol");
                if (protocol != null)
                    toReturnCisco.put(Constants.Fields.PROTOCOL.getName(), protocol.toLowerCase());

                String action = (String) messageJson.get("action");
                if (action != null)
                    toReturnCisco.put("action", action.toLowerCase());

                String src_user = (String) messageJson.get("src_fwuser");
                if (src_user != null)
                    toReturnCisco.put("src_user", src_user);

                String dst_user = (String) messageJson.get("dst_fwuser");
                if (dst_user != null)
                    toReturnCisco.put("dst_user", dst_user);

                String user = (String) messageJson.get("user");
                if (user != null)
                    toReturnCisco.put("user", user);

                String action_description = (String) messageJson.get("action_description");
                if (action_description != null)
                    toReturnCisco.put("action_description", action_description);

            } else
                LOG.warn("[Metron] Message '{}' did not match pattern for ciscotag '{}'", toParse,
                        syslogJson.get("CISCOTAG"));
        }

        LOG.debug("[Metron] Final normalized cisco message: {}", toReturnCisco.toString());


        return toReturnCisco;
    }


    private JSONObject parseF5(String toParse) {
        JSONObject toReturnF5 = new JSONObject();

        Map<String, Object> f5Json = new HashMap<String, Object>();

        try {
            Grok f5Grok = grokers.get("f5");
            Match f5Match = f5Grok.match(toParse);
            f5Match.captures();
            if (!f5Match.isNull()) {
                f5Json = f5Match.toMap();
                LOG.trace("[Labs247] grok F5 syslog matches: {}", f5Match.toJson());


                if (f5Json.get("timestamp") != null) {
                    try {
                        toReturnF5.put(Constants.Fields.TIMESTAMP.getName(),
                                SyslogUtils.parseTimestampToEpochMillis((String) f5Json.get("timestamp"), deviceClock));
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                }

                if (f5Json.get("context_type") != null) {
                    toReturnF5.put("context_type", f5Json.get("context_type"));
                }

                if (f5Json.get("context_name") != null) {
                    toReturnF5.put("context_name", f5Json.get("context_name"));
                }

                if (f5Json.get("acl_policy_type") != null) {
                    toReturnF5.put("acl_policy_type", f5Json.get("acl_policy_type"));
                }

                if (f5Json.get("acl_policy_name") != null) {
                    toReturnF5.put("acl_policy_name", f5Json.get("acl_policy_name"));
                }

                if (f5Json.get("acl_rule_name") != null) {
                    toReturnF5.put("acl_rule_name", f5Json.get("acl_rule_name"));
                }

                if (f5Json.get("src_geo") != null) {
                    toReturnF5.put("src_city", f5Json.get("src_geo"));
                }

                if (f5Json.get("source_fqdn") != null) {
                    toReturnF5.put("src_fqdn", f5Json.get("source_fqdn"));
                }

                if (f5Json.get("src_ip") != null) {
                    toReturnF5.put("ip_src_addr", f5Json.get("src_ip"));
                }

                if (f5Json.get("src_port") != null) {
                    toReturnF5.put("ip_src_port", f5Json.get("src_port"));
                }

                if (f5Json.get("vlan") != null) {
                    toReturnF5.put("vlan", f5Json.get("vlan"));
                }

                if (f5Json.get("dest_geo") != null) {
                    toReturnF5.put("dst_city", f5Json.get("dest_geo"));
                }

                if (f5Json.get("dest_fqdn") != null) {
                    toReturnF5.put("dst_fqdn", f5Json.get("dest_fqdn"));
                }

                if (f5Json.get("dest_ip") != null) {
                    toReturnF5.put("ip_dst_addr", f5Json.get("dest_ip"));
                }

                if (f5Json.get("dest_port") != null) {
                    toReturnF5.put("ip_dst_port", f5Json.get("dest_port"));
                }

                if (f5Json.get("route_domain") != null) {
                    toReturnF5.put("route_domain", f5Json.get("route_domain"));
                }

                if (f5Json.get("protocol") != null) {
                    toReturnF5.put("protocol", f5Json.get("protocol"));
                }

                if (f5Json.get("action") != null) {
                    toReturnF5.put("action", f5Json.get("action"));
                }

                if (f5Json.get("drop_reason") != null) {
                    toReturnF5.put("drop_reason", f5Json.get("drop_reason"));
                }

            } else
                throw new RuntimeException(
                        String.format("[Metron] Message '%s' does not match pattern '%s'", toParse, f5FirewallPattern));
        } catch (RuntimeException e) {
            LOG.error(e.getMessage(), e);
        }

        return toReturnF5;
    }
}