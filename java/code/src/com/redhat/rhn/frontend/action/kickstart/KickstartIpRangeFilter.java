/**
 * Copyright (c) 2009--2010 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.redhat.rhn.frontend.action.kickstart;

import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.frontend.dto.kickstart.KickstartIpRangeDto;
import com.redhat.rhn.frontend.taglibs.list.BaseListFilter;
import com.redhat.rhn.frontend.xmlrpc.InvalidIpAddressException;
import com.redhat.rhn.manager.kickstart.IpAddress;
import com.redhat.rhn.manager.kickstart.IpAddressRange;

import java.util.Locale;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * KickstartIpRangeFilter
 * @version $Rev: 1 $
 */
public class KickstartIpRangeFilter extends BaseListFilter {

    /** Logger for this class */
    private static Logger log = Logger.getLogger(KickstartIpRangeFilter.class);

    /**
     * ${@inheritDoc}
     */
    public void processMap(Map map, Locale userLocale) {
        LocalizationService ls =
            LocalizationService.getInstance();
        String label = ls.getMessage("list.filter.iprange",
                userLocale);
        map.put(label, "iprange.range");
    }

    /**
     * ${@inheritDoc}
     */
    public boolean filter(Object object, String field,
            String criteria) {
        KickstartIpRangeDto range = (KickstartIpRangeDto) object;
        return filterOnRange(criteria, range.getMin(), range.getMax());
    }

    /**
     * Returns true if the search ip is within the min and max
     *  helper method used by filter and by other things
     * @param search the ip address to search for
     * @param min the min ipaddress
     * @param max the max ipaddress
     * @return true if it is contained, false otherwise
     */
    public boolean filterOnRange(String search, Long min, Long max) {
        // Try to create an IP address from the incoming string
        IpAddress searchIp = null;
        try {
            searchIp = new IpAddress(search);            
        } catch (InvalidIpAddressException iiae) {
            log.error(iiae.getMessage());
            return false;
        }

        IpAddressRange ipRange = new IpAddressRange(min, max);
        return ipRange.isIpAddressContained(searchIp);
    }
}
