package com.redhat.rhn.manager.content.debian.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.List;
import org.junit.Test;
import com.redhat.rhn.manager.content.debian.DebianErrataManager;
import com.redhat.rhn.testing.BaseTestCaseWithUser;
import com.redhat.rhn.domain.product.Tuple2;
import com.redhat.rhn.manager.content.debian.DebianErrataInfo;

public class DebianErrataManagerTest extends BaseTestCaseWithUser  {

    private List<DebianErrataInfo> prepareDSAList() throws IOException, ParseException {
        
        InputStream testData = DebianErrataManager.loadDebianDSAList();
        return DebianErrataManager.parseDebianErrata(testData);
    }

    @Test
    public void testErrataCount() throws IOException, ParseException {

        List<DebianErrataInfo> errataList = prepareDSAList();
        assertEquals("Total number of Errata objects should be 7", 7, errataList.size());
    }

    @Test
    public void testErrataSpecificData() throws IOException, ParseException {

        List<DebianErrataInfo> errataList = prepareDSAList();
        DebianErrataInfo dsa5672 = errataList.stream()
            .filter(e -> "DSA-5672-1".equals(e.getDsaNumber()))
            .findFirst()
            .orElse(null);

        assertNotNull("DSA-5672-1 should not be null", dsa5672);
        assertEquals("DSA-5672-1 should have 4 CVEs", 4, dsa5672.getCves().size());
    }

    @Test
    public void testErrataSummary() throws IOException, ParseException {

        List<DebianErrataInfo> errataList = prepareDSAList();
        DebianErrataInfo dsa5674 = errataList.stream()
            .filter(e -> "DSA-5674-1".equals(e.getDsaNumber()))
            .findFirst()
            .orElse(null);

        assertNotNull("DSA-5674-1 should not be null", dsa5674);
        assertEquals("Summary of DSA-5674-1 should match", "pdns-recursor - security update", dsa5674.getSummary());
    }

    @Test
    public void testPackageDetails() throws IOException, ParseException {

        List<DebianErrataInfo> errataList = prepareDSAList();
        DebianErrataInfo dsa5674 = errataList.stream()
            .filter(e -> "DSA-5674-1".equals(e.getDsaNumber()))
            .findFirst()
            .orElse(null);

        assertNotNull("DSA-5674-1 should not be null", dsa5674);
        assertEquals("DSA-5674-1 should have one package detail", 1, dsa5674.getPackageEVR().size());
        assertEquals("Package version for 'pdns-recursor' should match", true, dsa5674.getPackageEVR().contains(new Tuple2<String, String>("pdns-recursor", "4.8.8-1"))); 

        DebianErrataInfo dsa5670 = errataList.stream()
            .filter(e -> "DSA-5670-1".equals(e.getDsaNumber()))
            .findFirst()
            .orElse(null);

        assertNotNull("DSA-5670-1 should not be null", dsa5670);
        assertEquals("DSA-5670-1 should have two packages", 2, dsa5670.getPackageEVR().size());
        assertEquals("Package version for 'thunderbird' should match", true, dsa5670.getPackageEVR().contains(new Tuple2<String, String>("thunderbird", "1:115.10.1-1~deb11u1"))); 
        assertEquals("Package version for 'thunderbird' should match", true, dsa5670.getPackageEVR().contains(new Tuple2<String, String>("thunderbird", "1:115.10.1-1~deb12u1"))); 
    }
}
