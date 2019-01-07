package org.jumbofile.darkt.Main;

import org.jumbofile.darkt.reports.htmlPull;

public class Main {
    public static void main (String[] args){
        htmlPull pull = new htmlPull();
        String baseURL = "DARKTRACE_IP";
        try {
            pull.readJsonFromUrl(baseURL + "DARKTRACE_URL");
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
