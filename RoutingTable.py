"""
CS3640 | Fall 2021 | Assignment 3
BGP Routing Tables and Identifying BGP Hijacks

RoutingTable.py
---------------
The class in this file contains methods to apply route information to create,
update, and compress a routing table. You will need to implement methods to
take in BGP announcements and add any new path information to your routing
table, remove any entries that are no longer valid (have been withdrawn by the
announcing AS), and compress your routing table by merging together equivalent
entries.

"""

from ParseUpdates import ParseUpdates
import sys
import ipaddress
import time
import logging

root = logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)-4d: %(message)s',
                    datefmt='%m-%d %H:%M', filename="a3-bgp.log", filemode="w")


class RoutingTable:
    """
        Class for updating routing tables.
    """
    def __init__(self):
        """
        self.routing_table is a dictionary keyed by destination IP range and
        contains the shortest route available to reach that range.

        self.time_of_earliest_update and self.time_of_latest_update are the
        first and last timestamps of the updates that were used to construct
        self.routing_table.

        self.total_updates_received is the number of updates that were
        processed for this routing table.

        self.total_paths_changed is the number of times you either updated
        any entry in the routing table with a shorter path from another
        announcement or removed an entry from the routing table.

        self.reachability is the number of unique IP addresses that you have
        a path to using this routing table.

        All these parameters will be updated as you complete checkpoints 3-5.
        """
        self.routing_table = {}
        self.time_of_earliest_update, self.time_of_latest_update = sys.maxsize, 0
        self.total_updates_received, self.total_paths_changed = 0, 0
        self.reachability = 0

    def apply_announcement(self, announcement):
        """
        Checkpoint ID: 2 [1 point]
        This method takes the supplied announcement and then does the following:
            - update the `total_updates_received` attribute.
            - Update the time_of_earliest_update and time_of_latest_update
                attributes.
            - Check if entry an already exists in our routing table for
                destination block advertised by announcement.
            - If an entry exists, you will check to see if the path advertised
                by announcement is shorter than the path available through the
                current entry. If it is, then you will update the corresponding
                entry in the `routing_table` attribute and update the
                `total_paths_changed` attribute.
            - If no entry exists, create a new entry in the `routing_table`
                attribute for the destination range advertised by announcement.

        Routing table format: The routing table will be stored as a dictionary
            of dictionaries in the `routing_table attribute`. The dictionary
            will be keyed by the destination's CIDR IP range. Each value is
            a dictionary containing source_as, timestamp, as_path, and
            next_hop entries.

        :param announcement: This dictionary contains entries for timestamp,
        source_as, next_hop, as_path, and range.
        :return: True if no exceptions. False otherwise.
        """
        ###
        # fill in your code here
        ###

    def apply_withdrawal(self, withdrawal):
        """
        Checkpoint ID: 2 [1 point]
        This method takes a route withdrawal update and does the following:
            - Update the total_updates_received attribute.
            - Update the time_of_earliest_update and time_of_latest_update
                attributes.
            - Check if entry an already exists in our routing table for
                destination block advertised by withdrawal.
            - If an entry exists, you will check to see if the source of the
                update is the same as the source of the current entry. If it
                is, then you will delete the corresponding entry in the
                routing_table attribute and update the total_paths_changed
                attribute.
            - If no entry exists (with the same source), you can ignore the
                update.

        :param withdrawal: This dictionary contains entries for timestamp,
        source_as, and range.
        :return: True if no exceptions. False otherwise.
        """
        ###
        # fill in your code here
        ###

    def measure_reachability(self):
        """
        Checkpoint ID: 3 [1 point]
        This function will report the number of unique of IP addresses that are
        reachable by the router with this routing table.
            - Find CIDR blocks in your routing table that can be collapsed
                into a single CIDR block. For example: 100.0.0.0/24 and
                10.0.0.0/16 are two different entries that can both reach
                10.0.0.0-255.
            - Collapse these blocks (do not modify your routing table
                while doing so!)
            - Count how many unique IP address are contained in the
                collapsed CIDR blocks.
            - Update the `self.reachability` parameter with this number.

        :return:
        """
        ###
        # fill in your code here
        ###

    def collapse_routing_table(self):
        """
        Checkpoint ID: 4 [3 points]
        This function will check to see if there are redundant entries in
        routing_table and collapse them into a single entry.
            - For each entry in routing_table, check to see if there is another
                entry whose: (1) destination CIDR IP block completely contains
                it and (2) has the same source_as, as_path, and next_hop
                attributes. If such a match exists, then delete the one with
                the longest prefix.
            - If you merge records, update the timestamp attribute to the
                max of all the entries being merged.

        Important: Doing pairwise comparisons is prohibitively expensive and
        will likely run for a long time. Think of more clever ways to collapse
        entries or rules that can filter out a large number of comparisons.
        :return: True if no exceptions occurred. False if an exception occurred.
        """
        ###
        # fill in your code here
        ###

    def find_path_to_destination(self, destination):
        """
        Checkpoint ID: 5 [2 points]
        This function figures out what route an incoming packet should take to
        reach its destination ip address. If there are multiple paths that are
        available, it will return them all in order of decreasing CIDR prefix.
        You will implement "longest prefix match" routing.
        https://en.wikipedia.org/wiki/Longest_prefix_match.

            - Find all paths that are available to a destination IP.
            - Sort them in order of prefix length, so that the longest prefix
                is the first entry in the list.
            - Return a list of {"as_path": <as_path>, "next_hop": <next_hop>,
                "prefix_len": <prefix len>, "source_as": <source_as>}
                dictionaries sorted in decreasing order of the prefix length
                of the CIDR block that the corresponding routing table entry
                was for. Return [{"as_path": None, "next_hop": None,
                "prefix_len": None, "source_as": None}] if there are exceptions.

        :param destination: An IPv4 address as a *string* object.
        :return: Best route for a supplied destination IPv4 address (see format
            above).
        """
        ###
        # fill in your code here
        ###

    def helper_print_routing_table_descriptions(self, collapse=False):
        """
        Helper function that prints statistics associated with the current
        routing table.
        :param collapse: True if the routing table should be collapsed
        before stats are computed.
        :return:
        """
        if collapse:
            self.collapse_routing_table()
        self.measure_reachability()
        s = "Earliest update seen: %d, \t Latest update seen: %d" % (self.time_of_earliest_update,
                                                                     self.time_of_latest_update)
        s += "\nTotal updates received: %d, \t " \
             "Total number of path changes observed: %d" % (self.total_updates_received, self.total_paths_changed)
        s += "\nTotal number of routing table entries currently in table: %d" % len(self.routing_table.keys())
        s += "\nReachable addresses of the IPv4 space from current table: %d" % self.reachability
        print(s)
        logging.info(s)


def main():
    pu = ParseUpdates(filename="./data/updates.20080219.0015.bz2")
    rt = RoutingTable()
    pu.parse_updates()
    # pu.to_json_helper_function("./test.json")
    updates = pu.get_next_updates()
    while True:
        next_updates = updates.next()
        if next_updates['timestamp'] is None:
            logging.info("No more updates to process in file: %s" % pu.filename)
            break
        else:
            for announcement in next_updates["announcements"]:
                rt.apply_announcement(announcement)
            for withdrawal in next_updates["withdrawals"]:
                rt.apply_withdrawal(withdrawal)
    rt.measure_reachability()
    rt.helper_print_routing_table_descriptions()
    rt.helper_print_routing_table_descriptions(collapse=True)
    for destination in ["8.8.8.8", "125.161.0.1"]:
        paths = rt.find_path_to_destination(unicode(destination))
        for idx, path in enumerate(paths):
            print(idx, destination, path)


if __name__ == '__main__':
    main()
