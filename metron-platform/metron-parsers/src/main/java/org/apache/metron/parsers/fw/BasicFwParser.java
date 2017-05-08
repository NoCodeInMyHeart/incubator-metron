package org.apache.metron.parsers.fw;

import org.apache.metron.parsers.BasicParser;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Created by yh on 2017/5/4.
 */
public class BasicFwParser extends BasicParser{

    protected static final Logger _LOG = LoggerFactory.getLogger(BasicFwParser.class);


    private static String defaultDateFormat = "yyyy-MM-dd HH:mm:ss";
    private transient DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(defaultDateFormat);

    @Override
    public void configure(Map<String, Object> config) {

    }


    @Override
    public void init() {

    }

    @Override
    @SuppressWarnings("unchecked")
    public List<JSONObject> parse(byte[] msg) {
        _LOG.trace("[Metron] Starting to parse incoming message");

        JSONObject payload = new JSONObject();
        String toParse = "";
        List<JSONObject> messages = new ArrayList<>();

        try {
            toParse = new String(msg, "UTF-8");
            _LOG.trace("[Metron] Received message: " + toParse);

            String time = toParse.substring(toParse.indexOf("%",0) + 1,toParse.indexOf(" ",toParse.indexOf("%",0)) + 9);
            Long timestamp = toEpoch(time);
            payload.put("timestamp",timestamp);

            String protocol = toParse.substring(toParse.indexOf("=",toParse.indexOf("proto")) + 1,toParse.indexOf(" ",toParse.indexOf("=",toParse.indexOf("proto"))));
            payload.put("protocol",protocol);

            String ip_src_addr = toParse.substring(toParse.indexOf("=",toParse.indexOf("srcip")) + 1,toParse.indexOf(" ",toParse.indexOf("=",toParse.indexOf("srcip"))));
            payload.put("ip_src_addr",ip_src_addr);

            String ip_dst_addr = toParse.substring(toParse.indexOf("=",toParse.indexOf("dstip")) + 1,toParse.indexOf(" ",toParse.indexOf("=",toParse.indexOf("dstip"))));
            payload.put("ip_dst_addr",ip_dst_addr);

            String ip_src_port = toParse.substring(toParse.indexOf("=",toParse.indexOf("sport")) + 1,toParse.indexOf(" ",toParse.indexOf("=",toParse.indexOf("sport"))));
            payload.put("ip_src_port",ip_src_port);

            String ip_dst_port = toParse.substring(toParse.indexOf("=",toParse.indexOf("dport")) + 1,toParse.indexOf(" ",toParse.indexOf("=",toParse.indexOf("dport"))));
            payload.put("ip_dst_port",ip_dst_port);
            payload.put("source.type","log");

            messages.add(payload);
            return messages;

        }catch (Exception e){
            String message = "Unable to parse Message: " + toParse;
            _LOG.error(message, e);
            throw new IllegalStateException(message, e);
        }
    }

    private long toEpoch(String snortDatetime) throws ParseException {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(snortDatetime.trim(), dateTimeFormatter);
        return zonedDateTime.toInstant().toEpochMilli();
    }

    @Override
    public Optional<List<JSONObject>> parseOptional(byte[] parseMessage) {
        return null;
    }
}
