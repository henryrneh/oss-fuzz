import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.glassfish.jersey.message.internal.HttpHeaderReader;
import org.glassfish.jersey.message.internal.MatchingEntityTag;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;

import java.text.ParseException;

public class HttpHeaderReaderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		try {
			HttpHeaderReader.readMatchingEntityTag(data.consumeString(50));
			HttpHeaderReader.readQualityFactor(data.consumeString(50));
			HttpHeaderReader.readDate(data.consumeString(50));
			HttpHeaderReader.readAcceptToken(data.consumeString(50));
			HttpHeaderReader.readAcceptLanguage(data.consumeString(50));
			HttpHeaderReader.readStringList(data.consumeString(50));
			HttpHeaderReader.readCookie(data.consumeString(50));
			HttpHeaderReader.readCookies(data.consumeString(50));
			HttpHeaderReader.readNewCookie(data.consumeRemainingAsString());

		} catch (ParseException pe) { }
	} 
}