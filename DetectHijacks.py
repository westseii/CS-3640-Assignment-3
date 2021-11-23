"""
CS3640 | Fall 2021 | Assignment 3
BGP Routing Tables and Identifying BGP Hijacks

DetectHijacks.py
---------------
The class in this file contains methods to identify and log suspicious BGP
announcements. You will need to implement methods to check whether an issued
update is safe to be applied to your routing table and log information about
updates that are deemed unsafe. Using these logs, you will be able to
understand exactly how BGP hijacks work and how they can be used to implement
censorship.
"""


import json
from RoutingTable import RoutingTable
from ParseUpdates import ParseUpdates
import datetime
import logging
import ipaddress


class DetectHijacks:
    """
        Class for identifying and logging suspicious updates and applying
        safe updates to a routing table.
    """

    def __init__(self, start_table, monitored_range):
        """
        :param start_table: The routing table to which updates are to be
        monitored.
        :param monitored_range: The destination range for which updates are
        to be monitored.
        """
        self.routing_table = start_table
        self.monitored_range = monitored_range
        self.expected_as, self.expected_as_org = None, None
        self.all_announcements_to_monitored_range = []
        self.suspicious_announcements_to_monitored_range = []
        self.asn_to_org_dictionary = {}
        self.asn_to_organization_mapper()

    def update_routing_table_safely(self, mrt_files):
        """
        Checkpoint ID: 6 [3 points]
        In this method, you will apply all the updates from the supplied list
        of MRT files to the routing table in `self.routing_table`.

        You will need to do the following:
            - Identify suspicious updates that are associated with the
                monitored range. These are updates that appear to show
                the destination range in a different AS number than the
                prior announcements. For example, if you know that IP range
                `8.8.8.8/24` belongs in AS X, it would be suspicious if you
                saw an announcement which indicated that `8.8.8.8/24` or any
                other contained subnet belonged in AS Y. You may use the first
                announcement observed for any range as your guide for the
                `self.expected_as` and `self.expected_as_org`.
            - Log the suspicious updates in
                `self.suspicious_announcements_to_monitored_range`. Make sure
                to use the logging mechanism to log the legitimate announcements
                and suspicious announcements for the range. Your logging messages
                should indicate the timestamp of the announcement, the AS number
                and AS organization expected to be seen, and the AS number and
                AS organization actually seen making the announcement for the
                destination range.
            - Apply only all the safe announcements to the routing table
                contained in self.routing_table.

        :param mrt_files: A list of MRT files from which updates will be
            processed.
        :return:
        """
        ###
        # fill in your code here
        ###



        networks = ipaddress.ip_network(self.monitored_range, False)
        set = False
        for mrt in mrt_files:
            pu = ParseUpdates(mrt)
            pu.parse_updates()
            updates = pu.get_next_updates()
            while True:
                next_updates = next(updates)
                if next_updates['timestamp'] is None:
                    break
                else:
                    for announcement in next_updates["announcements"]:
                        network = ipaddress.IPv4Network(announcement['range']['prefix'], False)
                        if announcement['range']['prefix'] not in self.routing_table.routing_table:
                            self.routing_table.apply_announcement(announcement)
                            if network.subnet_of(networks):
                                if not set:
                                    self.expected_as = announcement['as_path']["value"][0]["value"][-1]
                                    self.expected_as_org = self.get_org(self.expected_as)
                                    logging.info("[@t={}] First announcement for destination: {}, (AS: {}, {})".format(
                                        announcement['timestamp'], announcement['range']['prefix'], self.expected_as, self.expected_as_org))
                                    set = True
                                elif self.expected_as != announcement['as_path']["value"][0]["value"][-1]:
                                    interactions_sus = {
                                        'timestamp': announcement['timestamp'],
                                        'as_num_expected' : self.expected_as,
                                        'as_org_expected' : self.expected_as_org,
                                        'as_num_actual' : announcement['as_path']["value"][0]["value"][-1],
                                        'as_org_actual' : self.get_org(announcement['as_path']["value"][0]["value"][-1])
                                    }
                                    logging.info("[@t={}], Suspicious announcement for destination: {}. Expected destination AS: {} ({}), but observed AS: {} ({}) instead".format(
                                        announcement['timestamp'], announcement['range']['prefix'], self.expected_as, self.expected_as_org, 
                                        announcement['as_path']["value"][0]["value"][-1], 
                                        self.get_org(announcement['as_path']["value"][0]["value"][-1])))
                                    self.suspicious_announcements_to_monitored_range.append(interactions_sus)
                                    self.all_announcements_to_monitored_range.append(interactions_sus)
                                else:
                                    self.routing_table.apply_announcement(announcement)
                                    interactions_safe = {"timestamp": announcement["timestamp"], "range": announcement['range'], 
                                                        "as": self.expected_as, "org": self.expected_as_org}
                                    self.all_announcements_to_monitored_range.append(interactions_safe)
                                    logging.info('[@t={}] Announcement for destination: {} (AS: {}, {})'.format(interactions_safe['timestamp'], 
                                        announcement['range'], interactions_safe['as'], interactions_safe['org']))
                        else:
                            if network.subnet_of(networks):
                                if self.expected_as == announcement["as_path"]["value"][0]["value"][-1]:
                                    self.routing_table.apply_announcement(announcement)
                                    interactions_safe = {
                                        'timestamp': announcement['timestamp'],
                                        'range' : announcement['range']['prefix'],
                                        'as_num' : self.expected_as,
                                        'as_org' : self.expected_as_org
                                    }
                                    self.all_announcements_to_monitored_range.append(interactions_safe)
                                    logging.info("[@t={}] Announcement for destination: {} (AS: {}, {})".format(
                                        interactions_safe['timestamp'], announcement['range']['prefix'], interactions_safe['as_num'],
                                        interactions_safe['as_org']))
                                else:
                                    interactions_sus = {
                                        'timestamp': announcement['timestamp'],
                                        'as_num_expected' : self.expected_as,
                                        'as_org_expected' : self.expected_as_org,
                                        'as_num_actual' : announcement['as_path']["value"][0]["value"][-1],
                                        'as_org_actual' : self.get_org(announcement['as_path']["value"][0]["value"][-1])
                                    }
                                    logging.info("[@t={}], Suspicious announcement for destination: {}. Expected destination AS: {} ({}), but observed AS: {} ({}) instead".format(
                                        announcement['timestamp'], announcement['range']['prefix'], self.expected_as, self.expected_as_org, 
                                        announcement['as_path']["value"][0]["value"][-1], 
                                        self.get_org(announcement['as_path']["value"][0]["value"][-1])))
                                    self.suspicious_announcements_to_monitored_range.append(interactions_sus)
                                    self.all_announcements_to_monitored_range.append(interactions_sus)
                            else:
                                self.routing_table.apply_announcement(announcement)

                                
    def get_org(self, asn):
        """
        Helper function that returns the name of the organization that owns a
        specific AS number.

        :param asn: AS number
        :return:
        """
        try:
            org = self.asn_to_org_dictionary[asn]
            return org
        except KeyError:
            return "UNKNOWN"

    def asn_to_organization_mapper(self):
        """
        Uses AS2Org mappings from CAIDA to build a dictionary of AS number to
        organization name mappings.

        :return:
        """
        logging.info("Building ASN to Org dictionary")
        with open("./data/20211001.as-org2info.jsonl", encoding='cp850') as fp:
            for line in fp:
                record = json.loads(line)
                try:
                    self.asn_to_org_dictionary[record["asn"]] = record["name"]
                except KeyError:
                    continue
        logging.info("ASN to Org dictionary built. %d mappings found" %
                     len(self.asn_to_org_dictionary.keys()))


def main():
    rt = RoutingTable()
    dh = DetectHijacks(start_table=rt, monitored_range='208.65.153.0/21')
    files = ["./data/updates.20080222.0208.bz2", "./data/updates.20080224.1839.bz2", "./data/updates.20080224.2009.bz2",
             "./data/updates.20080224.2026.bz2", "./data/updates.20080224.2041.bz2", "./data/updates.20080224.2056.bz2"]
    dh.update_routing_table_safely(files)
    dh.routing_table.helper_print_routing_table_descriptions()


if __name__ == '__main__':
    main()
