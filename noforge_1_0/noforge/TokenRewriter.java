import java.io.*;
import java.util.*;
import org.htmlparser.*;
import org.htmlparser.util.*;
import org.htmlparser.lexer.*;
import org.htmlparser.visitors.*;
import org.htmlparser.tags.*;

public class TokenRewriter {

    private String tokenName;
    private String tokenValue;
    private boolean appendToAbsolute;
    
    public TokenRewriter (String tokenName, String tokenValue) {
        this.tokenName = tokenName;
        this.tokenValue = tokenValue;
        this.appendToAbsolute = false;
    }


    // invocation:
    // HTML file to be converted: standard input
    // 0: token name
    // 1: token value
    public static void main(String[] args) {

        // read HTML file from stdin
        String html = null;
        try {
            StringBuffer inputBuffer = new StringBuffer();
            int cbuflen = 10000;
            char[] cbuf = new char[cbuflen];
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            int readChars = reader.read(cbuf, 0, cbuflen);
            while (readChars != -1) {
                inputBuffer.append(cbuf, 0, readChars);
                readChars = reader.read(cbuf, 0, cbuflen);
            }
       
            html = inputBuffer.toString();

            //File file = new File("/tmp/outfile.txt");
            //FileWriter writer = new FileWriter(file);
            //writer.write(html);
            //writer.close();
 
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.out.println(e.getStackTrace()); 
            System.exit(1);
        }
        // String html = "<html><p>Hello World!<a href=\"target1.php\">bla1</a>, <a href=\"target2.php?xy=ab\">bla2</a></p></html>";

        if (args.length != 2) {
           System.out.println("Please provide tokenName and tokenValue as parameters");
           System.exit(1); 
        }

        String tokenName = args[0];
        String tokenValue = args[1];

        StringBuffer outputHtml = new StringBuffer();
        Lexer lexer = new Lexer(html);
        TokenRewriter tokenRewriter = new TokenRewriter(tokenName, tokenValue);
        
        try {
            Node node = lexer.nextNode();
            while (node != null) {
                if (node instanceof Tag) {
                    tokenRewriter.visitTag((Tag) node);
                }
                outputHtml.append(node.toHtml());
                node = lexer.nextNode();
            }
        } catch (ParserException ex) {
            System.err.println(ex.getMessage());
            System.err.println(ex.getStackTrace());
        }
        
        System.out.println(outputHtml);
    }


    public void visitTag(Tag tag) {
        
        String tagName = tag.getTagName();
        if (tagName == null) {
            return;
        }

        if (tagName.equals("HTML")) {
            // instrument the top HTML tag with an attribute xsrf_token="123456789";
            // -> you can easily access it with JavaScript using
            // document.getElementsByTagName("html")[0].getAttribute("xsrf_token"); 
            // NOTE: insert the appropriate "tokenName" for "xsrf_token"
            tag.setAttribute(this.tokenName, this.tokenValue, '"');
        } else if (tagName.equals("A")) {
            Attribute attr = tag.getAttributeEx("href");
            if (attr != null) {
                String rewriteString = attr.getValue();
                attr.setValue(this.appendToken(rewriteString));
            }
        } else if (tagName.equals("IMG")) {
            // necessary for PHP scripts that generate images (e.g., captcha's)
            Attribute attr = tag.getAttributeEx("src");
            if (attr != null) {
                String rewriteString = attr.getValue();
                attr.setValue(this.appendToken(rewriteString));
            }
        } else if (tagName.equals("FORM")) {
            Attribute attr = tag.getAttributeEx("action");
            if (attr != null) {
                String rewriteString = attr.getValue();
                attr.setValue(this.appendToken(rewriteString));
            }
        } else if (tagName.equals("FRAME") || tagName.equals("IFRAME")) {
            Attribute attr = tag.getAttributeEx("src");
            if (attr != null) {
                String rewriteString = attr.getValue();
                attr.setValue(this.appendToken(rewriteString));
            }
        } else if (tagName.equals("META")) {
            Attribute attr = tag.getAttributeEx("http-equiv");
            if (attr != null) {
                if (attr.getValue().equalsIgnoreCase("refresh")) {
                    // "refresh" meta tag
                    Attribute contentAttr = tag.getAttributeEx("content");
                    if (contentAttr != null) {

                        String content = contentAttr.getValue();
                        String lowerContent = content.toLowerCase();
                        
                        // should contain a suffix starting with "URL="
                        int urlIndex = lowerContent.indexOf("url=");
                        if (urlIndex != -1) {
                            String extracted = content.substring(urlIndex + 4);
                            this.appendToAbsolute = true;
                            String extractedAndModified = this.appendToken(extracted);
                            this.appendToAbsolute = false;
                            String newContent = content.substring(0, urlIndex + 4) + extractedAndModified;
                            contentAttr.setValue(newContent);
                        }


                    }
                }
            }
        } else if (tagName.equals("BUTTON")) {
            // encountered in Coppermine Photo Gallery
            String onclick = tag.getAttribute("onclick");
            if (onclick != null) {
                int hrefIndex = onclick.indexOf("location.href");
                if (hrefIndex != -1) {
                    String rest = onclick.substring(hrefIndex + 13);
                    int singleQuoteIndex = rest.indexOf('\'');
                    int doubleQuoteIndex = rest.indexOf('"');
                    int quoteIndex;
                    if (singleQuoteIndex == -1) {
                        quoteIndex = doubleQuoteIndex;
                    } else if (doubleQuoteIndex == -1) {
                        quoteIndex = singleQuoteIndex;
                    } else {
                        quoteIndex = Math.min(singleQuoteIndex, doubleQuoteIndex);
                    }
                    if (quoteIndex != -1) {
                        char quote = rest.charAt(quoteIndex);
                        int rightQuoteIndex = rest.lastIndexOf(quote);
                        if (rightQuoteIndex != -1) {
                            String extracted = rest.substring(quoteIndex + 1, rightQuoteIndex).trim();
                            String extractedAndModified = this.appendToken(extracted);
                            String newOnclick = onclick.substring(0, hrefIndex + 13 + quoteIndex + 1) + extractedAndModified + 
                                onclick.substring(hrefIndex + 13 + rightQuoteIndex);
                            tag.setAttribute("onclick", newOnclick);
                        }
                    }
                }
            }
        }
    }
    
    // appends "[&|?]tokenName=tokenValue" to the given link and returns it; the link must
    // satisfy the following conditions:
    // - it is a link to a .php script 
    // - it is a relative link or an absolute link with a given server prefix
    private String appendToken(String link) {
        
        String beforeParams;   // all that comes before the parameter list (excluding '?')
        String params;         // the parameters list (including '?'), can be null if there is none
        
        int indexOfQM = link.indexOf('?');
        if (indexOfQM == -1) {
            // this link has no parameters
            beforeParams = link;
            params = null;
        } else {
            // this link has parameters
            beforeParams = link.substring(0, indexOfQM);
            params = link.substring(indexOfQM);
        }


        if (!beforeParams.endsWith(".php")) {
            // this link doesn't point to a php script
            // => nothing to do
            return link;
        }

        if (beforeParams.startsWith("http://") && !this.appendToAbsolute) {
            // absolute link
            // LATER: do nothing for now
            return link;
        } else {
            // relative link

            if (params == null) {
                params = "?" + this.tokenName + "=" + this.tokenValue;
            } else {
                params += "&" + this.tokenName + "=" + this.tokenValue;
            }
        }
       
        return beforeParams + params;
    }

}


