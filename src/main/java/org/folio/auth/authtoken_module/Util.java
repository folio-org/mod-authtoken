package org.folio.auth.authtoken_module;

import io.vertx.core.json.JsonArray;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author kurt
 */
public class Util {
  public static boolean globMatch(String globPattern, String target) {
    String regexPattern = makeRegex(globPattern);
    Pattern pattern = Pattern.compile(regexPattern);
    return pattern.matcher(target).find();
  }

  public static boolean arrayContainsGlob(JsonArray array, String target) {
    for(Object o : array) {
      String s;
      s = (String)o;
      if(globMatch(s, target)) {
        return true;
      }
    }
    return false;
  }

  public static String makeRegex(String pattern) {
    Pattern regex = Pattern.compile("[^*]+|(\\*)");
    Matcher m = regex.matcher(pattern);
    StringBuffer b = new StringBuffer();
    while (m.find()) {
      if(m.group(1) != null) {
        m.appendReplacement(b, ".*");
      }
      else m.appendReplacement(b, "\\\\Q" + m.group(0) + "\\\\E");
    }
    m.appendTail(b);
    String replaced = b.toString();
    return replaced;
  }


}
