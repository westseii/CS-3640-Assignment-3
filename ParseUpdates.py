"""
CS3640 | Fall 2021 | Assignment 3
BGP Routing Tables and Identifying BGP Hijacks

ParseUpdates.py
---------------
The class in this file contains methods to parse BGP MRT files that contain
route announcements and withdrawals from peer ASes. You will need to
implement methods to read a supplied MRT file and extract specific information
about announced and withdrawn routes. You will then use this information to
build your routing table.

"""

from os import times
import mrtparse
import json
import time
import logging


class ParseUpdates:
    """
        Class for parsing updates recorded in BGP MRT dumps.
    """

    def __init__(self, filename):
        """
        :param filename: This is the MRT file to be parsed by the methods in
        this class. Sample files can be found in `./data/`.

        self.announcements and self.withdrawals are dictionaries that are keyed
        by timestamps and contain the list of all BGP route announcements and
        withdrawals at each timestamp.

        self.n_announcements and self.n_withdrawals are the number of route
        announcements and withdrawals observed in the supplied MRT file.

        You will update all these parameters as you complete checkpoints 1 & 2.
        """
        self.filename = filename
        self.announcements, self.withdrawals = {}, {}
        self.n_announcements, self.n_withdrawals = 0, 0
        self.time_to_parse = 0

    def parse_updates(self):
        """
        Checkpoint ID: 1 [1 point]
        In this function, you will read an MRT file using the `mrtparse` library.
        For each update in the MRT file, you will need to parse the timestamp,
        the peer_as that shared the update, and the bgp message containing the
        updates. You will then call the `__parse_announcement_updates` and
        `__parse_withdrawal_updates` methods with these parameters.

        :return: True if parsing was completed successfully. False otherwise.
        """
        start_time = time.time()
        ###
        # fill in your code here
        ###

        # get data from mrtparse
        for update in mrtparse.Reader(self.filename):

            # parse the update
            timestamp = update.data['timestamp'][0]
            peer_as = update.data['peer_as']
            bgp_message = update.data['bgp_message']  # bgp_message dict

            # run the appropriate functions
            self.__parse_announcement_updates(timestamp, peer_as, bgp_message)
            self.__parse_withdrawal_updates(timestamp, peer_as, bgp_message)

        # python3 Tests.py -cp 1

        ###
        self.time_to_parse = time.time() - start_time
        logging.info("Time taken to parse all records: %s second(s)" %
                     self.time_to_parse)
        logging.info("Routes announced: %s | Routes withdrawn: %s" %
                     (self.n_announcements, self.n_withdrawals))
        return True

    def __parse_announcement_updates(self, timestamp, peer_as, bgp_message):
        """
        Checkpoint ID: 1 [1 points]
        In this function, you will take a timestamp, peer_as, and bgp_message as
        input and then do the following:
            - increment n_announcements by the number of announced routes contained
                in bgp_message.
            - extract the advertised destination ip ranges from bgp_message.
            - extract the advertised AS path and next hop information from the bgp
                attributes in bgp_message.
            - create a dictionary named `update` which has the following keys
                populated by the data you just extracted: timestamp, range (this
                is the advertised CIDR IP address range being announced), next_hop,
                peer_as, and as_path.
            - update the `self.announcements` attribute with this new record.
                `self.announcements` is a dictionary of lists keyed by `timestamp`.
                There will be multiple messages for a single timestamp, so
                make sure that you aren't overwriting any existing entries
                when you should be appending to the already existing entries
                instead.

        :param timestamp: Timestamp obtained from the BGP header.
        :param peer_as: Peer AS obtained from the BGP header.
        :param bgp_message: BGP message containing all updates.
        :return: True if announcements were properly recorded. False otherwise.
        """
        ###
        # fill in your code here
        ###

        dest_ip_range = bgp_message['nlri']

        next_hop, as_path = None, None

        '''
        next_hop = bgp_message['path_attributes']  # TODO!
        as_path = bgp_message['path_attributes']  # TODO!
        '''

        out = []

        for pre in dest_ip_range:
            update = {
                "timestamp": timestamp,
                "range": pre['prefix'],
                "next_hop": next_hop,
                "peer_as": peer_as,
                "as_path": as_path
            }

            out.append(update)

        self.announcements[timestamp] = out
        self.n_announcements += len(dest_ip_range)

        # python3 Tests.py -cp 1

        ###
        return True

    def __parse_withdrawal_updates(self, timestamp, peer_as, bgp_message):
        """
        Checkpoint ID: 1 [1 points]
        In this function, you will take a timestamp, peer_as, and bgp_message as
        input and then do the following:
            - increment n_withdrawals by the number of withdrawn routes contained
                in bgp_message.
            - create a dictionary named `update` which has the following keys
                populated by the data you just extracted: timestamp, range (this
                is the advertised CIDR IP address range being announced),
                peer_as, and as_path.
            - update the `self.withdrawals` attribute with this new record.
                `self.withdrawals` is a dictionary of lists keyed by `timestamp`.
                There will be multiple messages for a single timestamp, so
                make sure that you aren't overwriting any existing entries
                when you should be appending to the already existing entries
                instead.

        :param timestamp: Timestamp obtained from the BGP header.
        :param peer_as: Peer AS obtained from the BGP header.
        :param bgp_message: BGP message containing all updates.
        :return: True if announcements were properly recorded. False otherwise.
        """
        ###
        # fill in your code here
        ###

        withdrawn_routes = bgp_message['withdrawn_routes']

        as_path = None

        '''
        as_path = bgp_message['path_attributes']  # TODO!
        '''

        out = []

        for pre in withdrawn_routes:
            update = {
                "timestamp": timestamp,
                "range": pre['prefix'],
                "peer_as": peer_as,
                "as_path": as_path
            }

            out.append(update)

        self.withdrawals[timestamp] = out
        self.n_withdrawals += len(withdrawn_routes)

        # python3 Tests.py -cp 1

        ###
        return True

    def get_next_updates(self):
        """
        You do not need to implement anything in this method.

        This method simply yields the next collection of announcements and
        withdrawals when called. Records yielded are sorted by time.
        :return:
        """
        timestamps = sorted(
            list(set(self.announcements.keys()).union(set(self.withdrawals.keys()))))
        for timestamp in timestamps:
            update_record = {'announcements': [],
                             'withdrawals': [], 'timestamp': timestamp}
            if timestamp in self.announcements.keys():
                update_record['announcements'] = self.announcements[timestamp]
            if timestamp in self.withdrawals.keys():
                update_record['withdrawals'] = self.withdrawals[timestamp]
            yield update_record
        yield {'announcements': [], 'withdrawals': [], 'timestamp': None}

    def to_json_helper_function(self, destination_json):
        """
        This is a helper function that converts the MRT file saved in
        `self.filename` to a JSON file and saves it to disk.

        :param destination_json: The location at which to save the converted
        JSON file.
        """
        records = []
        for entry in mrtparse.Reader(self.filename):
            records.append(entry.data)
        with open(destination_json, "w") as fp:
            json.dump(obj=records, fp=fp, indent=2, sort_keys=False)


def main():
    pu = ParseUpdates(filename="./data/updates.20080219.0015.bz2")
    pu.parse_updates()
    pu.to_json_helper_function("./sample-mrt-in-json.json")
    logging.info("Time taken to parse all records: %s second(s)" %
                 pu.time_to_parse)
    logging.info("Routes announced: %s | Routes withdrawn: %s" %
                 (pu.n_announcements, pu.n_withdrawals))
    updates = pu.get_next_updates()
    while True:
        next_updates = next(updates)
        if next_updates['timestamp'] is None:
            logging.info("No more updates to process in file: %s" %
                         pu.filename)
            break
        else:
            logging.info("At timestamp: %s | %s announcements | %s withdrawals" % (next_updates['timestamp'],
                                                                                   len(
                                                                                       next_updates['announcements']),
                                                                                   len(next_updates['withdrawals'])))


if __name__ == '__main__':
    main()
