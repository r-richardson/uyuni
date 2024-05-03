package com.redhat.rhn.manager.content.debian;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.redhat.rhn.common.conf.Config;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.common.util.http.HttpClientAdapter;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.errata.Cve;
import com.redhat.rhn.domain.errata.CveFactory;
import com.redhat.rhn.domain.errata.Errata;
import com.redhat.rhn.domain.errata.ErrataFactory;

import com.redhat.rhn.domain.product.Tuple2;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.PackageEvr;
import com.redhat.rhn.manager.content.ContentSyncManager;
import com.redhat.rhn.manager.content.MgrSyncUtils;
import com.redhat.rhn.manager.errata.ErrataManager;

public class DebianErrataManager {

        private static final Logger LOG = LogManager.getLogger(DebianErrataManager.class);

        /**
         * Syncs ubuntu errata information and matches it against the given channels
         * 
         * @param channelIds ids of channels to match erratas against
         * @throws IOException in case of download issues
         * @throws ParseException 
         */
        public static void sync(Set<Long> channelIds) throws IOException, ParseException {
                List<DebianErrataInfo> erratas;

                LOG.debug("sync started - check deb packages in channels, totalMemory:{}, freeMemory:{}",
                                Runtime.getRuntime().totalMemory(), Runtime.getRuntime().freeMemory());

                // Extract the deb packages from each channel
                List<Channel> channelList = channelIds.stream()
                                .map(ChannelFactory::lookupById)
                                .filter(c -> c.isTypeDeb() && !c.isCloned())
                                .collect(Collectors.toList());

                erratas = parseDebianErrata(loadDebianDSAList());
                processDebianErrata(channelList, erratas);
        }

        private static boolean isFromDir() {
                return Config.get().getString(ContentSyncManager.RESOURCE_PATH, null) != null;
        }

        public static InputStream loadDebianDSAList() throws IOException {
                String debianDsaUrl = "http://172.17.0.2/index.txt";
                if(isFromDir()){
                        URI uri = MgrSyncUtils.urlToFSPath(debianDsaUrl, "");
                        return new FileInputStream(uri.toString());
                }
                else {
                        return downloadDebianDSAList(debianDsaUrl);
                }
        }

        private static InputStream downloadDebianDSAList(String url) throws IOException {
                HttpClientAdapter httpClient = new HttpClientAdapter();
                HttpGet httpGet = new HttpGet(url);
                HttpResponse httpResponse = httpClient.executeRequest(httpGet);
                int statusCode = httpResponse.getStatusLine().getStatusCode();
                if (statusCode != HttpStatus.SC_OK) {
                        throw new IOException("Failed to download Debian DSA data, HTTP Status: " + statusCode);
                }
                InputStream content = httpResponse.getEntity().getContent();
                return content;
        }

        public static List<DebianErrataInfo> parseDebianErrata(InputStream inputStream) throws IOException, ParseException {
                try (BufferedReader reader = new BufferedReader(
                                new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                        List<DebianErrataInfo> erratas = new ArrayList<>();
                        DebianErrataInfo currentErrata = null;

                        String line;
                        while ((line = reader.readLine()) != null) {
                                String line_trimmed = line.trim();
                                if (line_trimmed.isEmpty())
                                        continue; // Skip empty lines
                                if (line.startsWith("[")) { // Start of a new DSA
                                        if (currentErrata != null) {
                                                erratas.add(currentErrata); // Add the completed DSA to the list
                                        }
                                        currentErrata = new DebianErrataInfo();
                                        String[] parts = line.split("] ", 2);
                                        currentErrata.setDate(parts[0].substring(1)); // Remove the leading '['
                                        String[] headerParts = parts[1].split(" ", 2);
                                        currentErrata.setDsaNumber(headerParts[0]);
                                        currentErrata.setSummary(headerParts[1].trim());
                                } else if (line_trimmed.startsWith("{")) { // CVEs
                                        line = line_trimmed.substring(1, line.length() - 1); // Remove '{' and '}'
                                        currentErrata.setCves(Arrays.asList(line.split(" ")));
                                } else if (line_trimmed.startsWith("[")) { // Package details
                                        line = line_trimmed;
                                        String[] packageParts = line.split("] - ", 2); // Split and disregard debian
                                                                                       // release name
                                        String[] packageInfo = packageParts[1].split(" ", 2);
                                        String packageName = packageInfo[0];
                                        String packageEVR = packageInfo[1];
                                        currentErrata.addPackageEVR(packageName, packageEVR);
                                }
                        }

                        if (currentErrata != null) {
                                erratas.add(currentErrata); // Add the last DSA if it exists
                        }
                        return erratas;
                }
        }

        private static void processDebianErrata(List<Channel> channels, List<DebianErrataInfo> dsaList){
                Set<Errata> changedErrata = new HashSet<>();
                for(Channel channel : channels) {       
                        for(DebianErrataInfo dsa : dsaList) {
                                for(Tuple2<String, String> evr_info : dsa.getPackageEVR()){
                                        PackageEvr evr = PackageEvr.parseDebian(evr_info.getB());
                                        List<Package> packages = getPackageListBySourcePackageName(channel, evr_info.getA(), evr);
                                        if (packages.isEmpty()){continue;}
                                        Errata errata = ErrataFactory.lookupByAdvisoryAndOrg(dsa.getDsaNumber(), channel.getOrg());
                                        if (errata == null){
                                                errata = new Errata();
                                                errata.setOrg(channel.getOrg());
                                                changedErrata.add(errata);
                                        }
                                        errata.setAdvisory(dsa.getDsaNumber());
                                        errata.setAdvisoryName(dsa.getDsaNumber());
                                        errata.setDescription(dsa.getSummary());
                                        errata.setIssueDate(dsa.getDate());
                                        errata.setProduct("Debian");
                                        errata.setSolution("-");
                                        errata.setSynopsis(dsa.getSummary());
                                        errata.setUpdateDate(dsa.getDate());
                                        
                                        Map<String, Cve> cveByName = errata.getCves().stream()
                                        .collect(Collectors.toMap(Cve::getName, cve -> cve));

                                        Set<Cve> cves = new HashSet<>();
                                        for (String cve_str : dsa.getCves()){
                                                Cve cve = cveByName.get(cve_str);
                                                if(cve == null){
                                                        cves.add(CveFactory.lookupOrInsertByName(cve_str));
                                                } else {
                                                   cves.add(cve);     
                                                }
                                        }
                                        errata.setCves(cves);

                                        Set<Package> packages_set = new HashSet<>(packages);
                                        if (errata.getPackages() == null) {
                                                errata.setPackages(packages_set);
                                                changedErrata.add(errata);
                                        }
                                        else if (errata.getPackages().addAll(packages_set)) {
                                                changedErrata.add(errata);
                                        }
                                        
                                        if (errata.getChannels().add(channel)){
                                                changedErrata.add(errata);
                                        }
                                        ErrataFactory.save(errata);
                                }
                        }
                }
                Set<Channel> channel_set = new HashSet<>();
                Map<Long, List<Long>> errataToChannels = new HashMap<>();

                for (Errata errata : changedErrata){
                        channel_set.addAll(errata.getChannels());
                        List<Long> channel_ids = new LinkedList<>();
                        for (Channel channel_info : errata.getChannels()){
                                channel_ids.add(channel_info.getId());
                        }
                        errataToChannels.put(errata.getId(), channel_ids);                        
                }
                for (Channel ch : channel_set){

                        LOG.debug("Update NeededCache for Channel: {}", ch.getLabel());
                        ErrataManager.insertErrataCacheTask(ch);
                }
                ErrataManager.bulkErrataNotification(errataToChannels, new Date());
        }

        private static List<Package> getPackageListBySourcePackageName(Channel channel, String sourcePackageName, PackageEvr evr){
                return HibernateFactory.getSession()
                        .createNamedQuery("Package.lookupByChannelAndSourcePackageName", Package.class)
                        .setParameter("channel_id", channel.getId())
                        .setParameter("epoch", evr.getEpoch())
                        .setParameter("version", evr.getVersion())
                        .setParameter("release", evr.getRelease())
                        .setParameter("source_package_name", sourcePackageName)
                        .list();
        }
}