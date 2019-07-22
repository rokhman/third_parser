package com.solusi247.labs.parser.proxy;


import com.google.common.base.Joiner;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import oi.thekraken.grok.api.Grok;
import oi.thekraken.grok.api.Match;
import oi.thekraken.grok.api.exception.GrokException;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.metron.parsers.BasicParser;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.lang.model.type.NullType;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.lang.invoke.MethodHandles;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.time.ZoneId;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BasicCustomProxyParser extends BasicParser {
    private static final long serialVersionUID = 6328907550159134550L;
    protected static final Logger LOG = LoggerFactory
            .getLogger(MethodHandles.lookup().lookupClass());

    private Grok syslogGrok;
    protected Clock deviceClock;
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy:MM:dd-HH:mm:ss");
    private String syslogPattern = "%{PROXY_TAGGED_SYSLOG}";

    private static final String nvRegex = "([-\\w\\d]+)=(\"[^=]*\")(?=\\s*[-\\w]+=|\\s*$)";
    private static final Pattern nvPattern = Pattern.compile(nvRegex);

    @Override
    public void configure(Map<String, Object> parserConfig) {
        String timeZone = (String) parserConfig.get("deviceTimeZone");
        if (timeZone != null)
            deviceClock = Clock.system(ZoneId.of(timeZone));
        else {
            deviceClock = Clock.systemUTC();
            LOG.warn("[Metron] No device time zone provided; defaulting to UTC");
        }

        String dateFormatParam = (String) parserConfig.get("dateFormat");
        if (dateFormatParam != null) {
            this.dateFormat = new SimpleDateFormat(dateFormatParam);
        }
    }

    @Override
    public void init() {
        syslogGrok = new Grok();
        InputStream patternStream = this.getClass().getResourceAsStream("/patterns/proxy");
        try {
            syslogGrok.addPatternFromReader(new InputStreamReader(patternStream));
            syslogGrok.compile(syslogPattern);
        } catch (GrokException e) {
            LOG.error("[Metron] Failed to load grok patterns from jar", e);
            throw new RuntimeException(e.getMessage(), e);
        }

        LOG.info("[Metron] Proxy Parser Initialized");
    }


    @Override
    @SuppressWarnings("unchecked")
    public List<JSONObject> parse(byte[] rawMessage) {
        String toParse;
        String dynamicMessage = "";
        JSONObject toReturn, resultParse;
        toReturn = new JSONObject();
        resultParse = new JSONObject();
        List<JSONObject> messages = new ArrayList<>();
        Map<String, Object> syslogJson = new HashMap<String, Object>();

        try {
            toParse = new String(rawMessage, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            LOG.error("[Metron] Could not read raw message", e);
            throw new RuntimeException(e.getMessage(), e);
        }

        try {

            LOG.debug("[Metron] Started parsing raw message: {}", toParse);

            Match syslogMatch = syslogGrok.match(toParse);
            syslogMatch.captures();
            if (!syslogMatch.isNull()) {
                syslogJson = syslogMatch.toMap();
                LOG.trace("[Metron] Grok PROXY syslog matches: {}", syslogMatch.toJson());

                toReturn.put("facility", syslogJson.get("facility"));

                if(syslogJson.get("PROXYTIMESTAMP") != null) {
                    String ts = (String) syslogJson.get("PROXYTIMESTAMP");
                    Date dt = dateFormat.parse(ts);
                    long epoch = dt.getTime();
                    toReturn.put("timestamp", epoch);
                }
                else {
                    toReturn.put("timestamp", System.currentTimeMillis());
                }


                toReturn.put("proxy_name", syslogJson.get("proxy_name"));
                toReturn.put("type", syslogJson.get("type"));

                if(syslogJson.get("message") != null) {
                    dynamicMessage = syslogJson.get("message").toString();

                    // parse the main message
                    resultParse = parseMessage(dynamicMessage);
                    if(!resultParse.isEmpty()) {
                        toReturn.putAll(resultParse);
                    }
                }
            }
            else
                throw new RuntimeException(
                        String.format("[Metron] Message '%s' does not match pattern '%s'", toParse, syslogPattern));

            toReturn.put("original_string", toParse);

            messages.add(toReturn);



            return messages;
        } catch (RuntimeException e) {
            LOG.error(e.getMessage(), e);
            throw new RuntimeException(e.getMessage(), e);
        } catch (ParseException e) {
            String message = "Unable to parse " + new String(rawMessage) + ": " + e.getMessage();
            LOG.error(message, e);
            throw new IllegalStateException(message, e);
        }
    }

    @SuppressWarnings("unchecked")
    private JSONObject parseMessage(String toParse) {

        JSONObject toReturn = new JSONObject();

        Multimap<String, String> multiMap = formatMain(toParse);

        for (String key : multiMap.keySet()) {
            String value = Joiner.on(",").join(multiMap.get(key));
            value = value.trim();

            if(key.equals("ip_dst_addr") && value.isEmpty()){
                toReturn.put(key, null);
            }
            else {
                toReturn.put(key, value);
            }

        }
        return toReturn;
    }

    private Multimap<String, String> formatMain(String in) {
        Multimap<String, String> multiMap = ArrayListMultimap.create();
        String input = in.replaceAll("\\bdstip\\b", "ip_dst_addr")
                .replaceAll("\\bsrcip\\b", "ip_src_addr");

        Matcher m = nvPattern.matcher(input);

        while (m.find()) {
            String[] str = m.group().split("=");
            str[1] = str[1].replaceAll("\"", "");
            multiMap.put(str[0], str[1]);
        }

        return multiMap;
    }

}
