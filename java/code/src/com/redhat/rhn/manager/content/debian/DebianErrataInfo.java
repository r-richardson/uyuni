package com.redhat.rhn.manager.content.debian;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import com.redhat.rhn.domain.product.Tuple2;

public class DebianErrataInfo {
    private Date date;
    private String dsaNumber;
    private String summary;
    private List<String> cves;
    private List<Tuple2<String, String>> evr;

    public DebianErrataInfo() {
        this.cves = new ArrayList<>();
        this.evr = new ArrayList<>();
    }

    public Date getDate() {
        return date;
    }

    public void setDate(String date_str) {
        SimpleDateFormat formatter = new SimpleDateFormat("dd MMM yyyy");
        try {
            this.date = formatter.parse(date_str);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid date format, expected 'dd MMM yyyy'", e);
        }
    }

    public String getDsaNumber() {
        return dsaNumber;
    }

    public void setDsaNumber(String dsaNumber) {
        if (dsaNumber != null && dsaNumber.startsWith("DSA-")) {
            this.dsaNumber = dsaNumber;
        } else {
            throw new IllegalArgumentException("DSA number must start with 'DSA-'");
        }
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getCves() {
        return Collections.unmodifiableList(cves);
    }

    public void setCves(List<String> cves) {
        if (cves != null) {
            for (String cve : cves) {
                if (!cve.startsWith("CVE-")) {
                    throw new IllegalArgumentException("All CVE entries must start with 'CVE-'");
                }
            }
            this.cves = new ArrayList<>(cves);
        } else {
            this.cves = new ArrayList<>();
        }
    }

    public void addPackageEVR(String pName, String pEVR) {
        evr.add(new Tuple2<>(pName, pEVR));
    }

    public List<Tuple2<String, String>> getPackageEVR() {
        return Collections.unmodifiableList(evr);
    }

    @Override
    public String toString() {
        return "DebianErrataInfo{" +
                "date='" + date + '\'' +
                ", dsaNumber='" + dsaNumber + '\'' +
                ", summary='" + summary + '\'' +
                ", cves=" + cves +
                ", packageDetails=" + evr +
                '}';
    }
}