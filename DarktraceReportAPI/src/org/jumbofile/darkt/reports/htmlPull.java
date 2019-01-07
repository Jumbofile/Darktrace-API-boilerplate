package org.jumbofile.darkt.reports;

import com.google.gson.*;
import org.json.JSONArray;
import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import static org.jumbofile.darkt.HMAC.HmacSha1Signature.calculateRFC2104HMAC;

/***
 * Pulls from darktrace using their api
 */
public class htmlPull {
    //Builds a string based of the buffered reasder input
    private String readAll(Reader rd) throws IOException {
        StringBuilder sb = new StringBuilder();
        int cp;
        //while there is a line
        while ((cp = rd.read()) != -1) {
            sb.append((char) cp);
        }

        //return the string that has been built
        return sb.toString();
    }

    //Reads the JSON data from darktrace
    public JSONArray readJsonFromUrl(String url) throws Exception {
        //GET RID OF THIS
        String api = "API KEY";

        //Force trust the certificate
        doTrustToCertificates();

        //New url
        URL u = new URL(url);

        //new conncetion
        HttpURLConnection conn = null;

        //New date in UTC time
        String date = Instant.now().toString();

        //Remove invalid data from the date
        date = date.substring(0, date.indexOf('.'));

        //Open a connection to the requested URL
        conn = (HttpURLConnection)u.openConnection();

        //Calculate the Signature of the request using the url + API Key + Date + Private Key
        String hmac = calculateRFC2104HMAC("DARK_TRACE_URL\n" + api + "\n" + date, "PRIVATE_KEY");

        /*
        HEADER OF THE CONNECTION
         */
        conn.setRequestMethod("GET");                       //Type of the request
        conn.setRequestProperty("DTAPI-Token", api);        //API Key, darktrace syntax
        conn.setRequestProperty("DTAPI-Date", date);        //Date, darktrace syntax
        conn.setRequestProperty("DTAPI-Signature", hmac);   //Signature calculated above, darktrace syntax

        //DEBUG
        System.out.println(date);
        System.out.println(api);
        System.out.println(hmac);

        //Send the connection and receive the input stream
        InputStream is = conn.getInputStream();
        try {
            //Read whats coming int the input stream
            BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));

            //Full json text
            String jsonText = readAll(rd);

            //Save the text to a JSONArray
            JSONArray json = new JSONArray(jsonText);

            //Gson gson = new GsonBuilder().setPrettyPrinting().create();
            //JsonParser jp = new JsonParser();
            //JsonElement je = jp.parse(json);
            //String prettyJsonString = gson.toJson(je);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            System.out.println("3-");
            System.out.println(gson.toJson(json));

            return json;
        } finally {
            is.close();
        }
    }

    /***
     * This tricks java into believing the certificate is valid, only have enabled if you know the URL
     * @throws Exception
     */
    public void doTrustToCertificates() throws Exception {
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        return;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        return;
                    }
                }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String urlHostName, SSLSession session) {
                if (!urlHostName.equalsIgnoreCase(session.getPeerHost())) {
                    System.out.println("Warning: URL host '" + urlHostName + "' is different to SSLSession host '" + session.getPeerHost() + "'.");
                }
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
    }
}