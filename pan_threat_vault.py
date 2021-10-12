#!/usr/bin/env python3
#
#  AUTHOR: Brad Atkinson
#    DATE: 4/15/2019
# PURPOSE: To pull the Threat Vault from a PAN device and parse to a CSV file

import os
import csv
import json
import config
import arrow
import logging
import logging.handlers as handlers
from pathlib import Path
from panos import panorama

# Directories
script_dir = Path('/usr/local/bin')
data_dir = script_dir / 'data'
log_dir = script_dir / 'log'

# Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    '%(asctime)s   Line: %(lineno)-4d   Func: %(funcName)-26s   Msg: %(message)s',
    datefmt='%m/%d %I:%M:%S %p')

log_file = log_dir / 'pan_threat_vault.log'
log_handler = handlers.TimedRotatingFileHandler(log_file,
                                                when='H',
                                                interval=1,
                                                backupCount=3)
log_handler.setLevel(logging.INFO)
log_handler.setFormatter(formatter)
logger.addHandler(log_handler)


def get_pano_connection():
    """
    Make Panorama connection

    Returns
    -------
    pano : Panorama
        A PanDevice for Panorama
    """
    logger.info('Connecting to device')
    key = config.paloalto['key']
    panorama_ip = config.paloalto['panorama_ip']

    pano = panorama.Panorama(hostname=panorama_ip, api_key=key)
    return pano


def get_threat_list(pano, xpath, find_path):
    """
    Get threat information (vulnerability, phone-home) and pass along to
    be processed

    Parameters
    ----------
    pano : Panorama
        A PanDevice for Panorama
    xpath : str
        A string containing the XML API path
    find_path : str
        A string containing the XML search path

    Returns
    -------
    threat_dict : dict
        A dictionary of strings containing threat information
    """
    logger.info('Gathering threat list')
    results = pano.op(cmd='<show><predefined><xpath>{}</xpath></predefined></show>'
        .format(xpath), cmd_xml=False)
    threat_xml_list = results.findall(find_path)
    threat_dict = process_threat_list(threat_xml_list)
    return threat_dict


def process_threat_list(threat_xml_list):
    """
    Process threat information to gather threat id, threat name, category,
    severity, default_action, engine_version, cve number, and affected_host,
    and add all items to a dictionary. Exceptions will be handled if items
    are not present in list by adding 'N/A' to the dictionary.

    Parameters
    ----------
    threat_xml_list : list
        A list containing the threat information output

    Returns
    -------
    threat_dict : dict
        A dictionary of strings containing threat information
    """
    logger.info('Processing threat list')
    threat_dict = {}

    for threat in threat_xml_list:
        threat_id_dict = threat.attrib
        threat_id = threat_id_dict.get('name')
        threat_name = threat.find('./threatname').text
        engine_ver_dict = threat.find('./engine-version').attrib
        engine_version = engine_ver_dict.get('min')
        severity = threat.find('./severity').text

        try:
            category = threat.find('./category').text
        except AttributeError:
            category = 'N/A'

        try:
            default_action = threat.find('./default-action').text
        except AttributeError:
            default_action = 'N/A'

        try:
            cve = threat.find('./cve/member').text
        except AttributeError:
            cve = 'N/A'

        try:
            threat.find('./affected-host/server').text
            affected_host = 'Server'
        except AttributeError:
            try:
                threat.find('./affected-host/client').text
                affected_host = 'Client'
            except AttributeError:
                affected_host = 'N/A'

        threat_dict[threat_id] = {'id': threat_id,
                                  'name': threat_name,
                                  'category': category,
                                  'severity': severity,
                                  'action': default_action,
                                  'version': engine_version,
                                  'cve': cve,
                                  'affected-host': affected_host}

    logger.debug(threat_dict)
    return threat_dict


def compare_dictionaries(threat_dict, stored_threat_dict, pano):
    """
    Check to see if the pulled threat info is in the stored threat dictionary
    to get the description, reference, and bugtraq information without doing
    an API call to gather that info.  Update stored threat dictionary with
    any new threats and delete existing threats from the threat dictionary to
    allow only new threats being added to CSV file. 

    Parameters
    ----------
    threat_dict : dict
        A dictionary of strings containing threat information
    stored_threat_dict : dict
        A dictionary of strings containing threat information stored to JSON
    pano : Panorama
        A PanDevice for Panorama

    Returns
    -------
    threat_dict : dict
        A dictionary of strings containing threat information
    stored_threat_dict : dict
        A dictionary of strings containing threat information stored to JSON
    """
    logger.info('Comparing dictionaries')
    updated_threat_dict = dict(threat_dict)

    for threat_id in threat_dict:
        if threat_id in stored_threat_dict:
            stored_threat = stored_threat_dict.get(threat_id)
            description = stored_threat.get('description')
            reference = stored_threat.get('reference')
            bugtraq = stored_threat.get('bugtraq')

            single_threat_dict = threat_dict.get(threat_id)
            single_threat_dict['description'] = description
            single_threat_dict['reference'] = reference
            single_threat_dict['bugtraq'] = bugtraq

            del updated_threat_dict[threat_id]
        else:
            threat_dict = get_threat_id_info(pano, threat_dict, threat_id)
            single_threat_dict = threat_dict.get(threat_id)
            stored_threat_dict[threat_id] = single_threat_dict

    threat_dict = dict(updated_threat_dict)
    logger.debug(threat_dict)
    return (threat_dict, stored_threat_dict)


def get_threat_id_info(pano, threat_dict, threat_id):
    """
    Get threat id information (vulnerability, phone-home) and pass along to
    be processed

    Parameters
    ----------
    pano : Panorama
        A PanDevice for Panorama
    threat_dict : dict
        A dictionary of strings containing threat information
    threat_id : str
        A string containing the threat id number

    Returns
    -------
    threat_dict : dict
        A dictionary of strings containing threat information
    """
    logger.info('Gathering thread id info')
    results = pano.op(cmd='<show><threat><id>{}</id></threat></show>'
        .format(threat_id), cmd_xml=False)
    threat_xml_list = results.findall('./result/entry')
    threat_dict = process_threat_id_info(threat_id, threat_xml_list,
        threat_dict)

    return threat_dict


def process_threat_id_info(threat_id, threat_xml_list, threat_dict):
    """
    Process threat id information to gather description, reference, and
    bugtraq, and add all items to a dictionary. Exceptions will be handled
    if items are not present in list by adding 'N/A' to the dictionary.

    Parameters
    ----------
    threat_id : str
        A string containing the threat id number
    threat_xml_list : list
        A list containing the threat information output
    threat_dict : dict
        A dictionary of strings containing threat information

    Returns
    -------
    threat_dict : dict
        A dictionary of strings containing threat information
    """
    logger.info('Processing threat id info')
    for threat in threat_xml_list:
        description = threat.find('./description').text
        description = description.rstrip()
        description = description.lstrip()

        try:
            reference = threat.find('./reference/member').text
        except AttributeError:
            reference = 'N/A'

        try:
            bugtraq = threat.find('./vulnerability/bugtraq/member').text
        except AttributeError:
            bugtraq = 'N/A'

        single_threat_dict = threat_dict.get(threat_id)
        single_threat_dict['description'] = description
        single_threat_dict['reference'] = reference
        single_threat_dict['bugtraq'] = bugtraq

    logger.debug(threat_dict)
    return threat_dict


def write_json(threat_dict, filename):
    """
    Write threat information to JSON for comparison when script is ran again

    Parameters
    ----------
    threat_dict : dict
        A dictionary of strings containing threat information
    filename : str
        A string containing the filename of the file
    """
    logger.info('Writing JSON file')
    with open(data_dir / '{}.json'.format(filename), 'w') as json_file:
        json.dump(threat_dict, json_file, indent=2)


def read_json(filename):
    """
    Read threat information from JSON for comparison and convert to dictionary

    Parameters
    ----------
    filename : str
        A string containing the filename of the file

    Returns
    -------
    threat_dict : dict
        A dictionary of strings containing threat information
    """
    logger.info('Reading JSON file')
    with open(data_dir / '{}.json'.format(filename), 'r') as json_file:
        threat_dict = json.load(json_file)
        return threat_dict


def parse_data_into_csv(threat_dict):
    """
    Write the contents of the dictionary information to a CSV file with the
    appropriate headers

    Parameters
    ----------
    threat_dict : dict
        A dictionary of strings containing threat information
    """
    logger.info('Parsing data into CSV file')
    date_time = arrow.now()
    date = date_time.format('YYYY-MM-DD')
    csv_filename = data_dir / 'threat_vault_{}.csv'.format(date)

    if os.path.isfile(csv_filename):
        os.remove(csv_filename)
        logger.debug('Removed {}'.format(csv_filename))

    with open(csv_filename, mode='a') as csv_file:
        fieldnames = [
            'id',
            'name',
            'category',
            'severity',
            'action',
            'version',
            'cve',
            'bugtraq',
            'affected-host',
            'description',
            'reference'
            ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for item in threat_dict.values():
            writer.writerow(item)


def gather_threat_info(pano, filename, xpath, find_path):
    """
    Read in stored threat info from JSON file, get new threat info from
    device, compare the new threat info to the stored info, write the
    updated stored info back to JSON, and for any new threats write data to
    a CSV file

    Parameters
    ----------
    pano : Panorama
        A PanDevice for Panorama
    filename : str
        A string containing the filename of the file
    xpath : str
        A string containing the XML API path
    find_path : str
        A string containing the XML search path
    """
    logger.info('Gathering threat info')
    stored_threat_dict = read_json(filename)
    threat_dict = get_threat_list(pano, xpath, find_path)
    threat_dict, stored_threat_dict = compare_dictionaries(threat_dict, 
        stored_threat_dict, pano)
    write_json(stored_threat_dict, filename)

    if len(threat_dict) != 0:
        parse_data_into_csv(threat_dict)


def main():
    """
    Set filename, API xpath, and XML search path for vulnerability and
    phone-home threats and proceed with gathering threat info
    """
    logger.info('Starting script')
    pano = get_pano_connection()

    logger.info('Vulnerability')
    filename = 'vulnerability'
    xpath = '/predefined/threats/vulnerability'
    find_path = './result/vulnerability/entry'
    gather_threat_info(pano, filename, xpath, find_path)

    logger.info('Phone Home')
    filename = 'phone-home'
    xpath = '/predefined/threats/phone-home'
    find_path = './result/phone-home/entry'
    gather_threat_info(pano, filename, xpath, find_path)

    logger.info('Finished script')


if __name__ == '__main__':
    main()
