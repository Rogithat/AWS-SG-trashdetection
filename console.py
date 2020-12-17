#!/usr/bin/env python

'''
Maintainer: Igor Santos Ferreira
Function: Cloud Analyst
Description: In order to avoid trash entries on our aws security groups, we must stabilish a description policy for every new entry on security-group.
In this case every description that matches with the regex tag must be revoked so all unecessary entries gets pruned

'''

import boto3
import emoji
import re

your_regex = ""
client = boto3.client('ec2')
security_group = client.describe_security_groups()


def delete_tmp_sg_ingress(security_group):

    for each_sg in security_group['SecurityGroups']:  # dict: SecurityGroups
        sg_id = each_sg['GroupId']                      # get group id
        for each_sg_option in each_sg['IpPermissions']:  # dict: IpPermissions
            try:
                from_port = each_sg_option['FromPort']      # get from port
            except:
                from_port = -1

            try:
                to_port = each_sg_option['ToPort']
            except:
                to_port = -1
            ip_protocol = each_sg_option['IpProtocol']

            for ip_ranges in each_sg_option['IpRanges']:  # dict: IpRanges
                cidr_ip = ip_ranges['CidrIp']           # get cidr_ip

# Filtering dict returned from the IpRanges key to show only 'Description' labeled keys and returns any SG ingress rule with 'Description': 'tmp'

                for x in ip_ranges.keys():
                    for y in ip_ranges.values():
                        regex = bool(re.search(
                            your_regex, y))
                        if (x == "Description") & regex:

                            print("Trash found on ", sg_id, "on ip rule ", cidr_ip,
                                  ip_protocol, emoji.emojize(':angry_face_with_horns:'))

                            try:
                                response = client.revoke_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[
                                        {
                                            'FromPort': from_port,
                                                                                        'IpProtocol': ip_protocol,
                                                                                        'IpRanges': [
                                                                                            {
                                                                                                'CidrIp': cidr_ip
                                                                                            },
                                                                                        ],
                                            'ToPort': to_port
                                            }
                                    ]
                                )

                            except:
                                print('An error has ocurred on rule deletion at SG: ', sg_id, ' Protocol: ', ip_protocol,
                                      ' please check your security group ingress rules', emoji.emojize(':no_entry:'))

                        else:
                            print('No trashes found on ', sg_id, ' Protocol: ', ip_protocol,
                                  ' in this ip rule ', cidr_ip, emoji.emojize(':thumbs_up:'))


def change_tag_from_sg(security_group):

    for each_sg in security_group['SecurityGroups']:  # dict: SecurityGroups
        sg_id = each_sg['GroupId']                      # get group id
        for each_sg_option in each_sg['IpPermissions']:  # dict: IpPermissions
            try:
                from_port = each_sg_option['FromPort']      # get from port
            except:
                from_port = -1

            #print(each_sg_option)
            try:
                to_port = each_sg_option['ToPort']          # get to port
            except:
                pass
            ip_protocol = each_sg_option['IpProtocol']

            for ip_ranges in each_sg_option['IpRanges']:  # dict: IpRanges
                cidr_ip = ip_ranges['CidrIp']           # get cidr_ip
    
                print('Changing ', sg_id, 'Protocol: ', ip_protocol,'From port: ', from_port, 'To port: ', to_port, 'IP: ', cidr_ip, ' description', emoji.emojize(':construction_worker:'))

                try:
                        response = client.update_security_group_rule_descriptions_ingress(
                            GroupId=sg_id,
                            IpPermissions=[
                                {
                                    'FromPort': from_port,
                                                                                'IpProtocol': ip_protocol,
                                                                                'IpRanges': [
                                                                                    {
                                                                                        'CidrIp': cidr_ip,
                                                                                        'Description': 'prod'
                                                                                    },
                                                                                ],
                                    'ToPort': to_port
                                    }
                            ]
                        )
                except:
                        response = client.update_security_group_rule_descriptions_ingress(
                            GroupId=sg_id,
                            IpPermissions=[
                                {
                                                                                'IpProtocol': ip_protocol,
                                                                                'IpRanges': [
                                                                                    {
                                                                                        'CidrIp': cidr_ip,
                                                                                        'Description': 'prod'
                                                                                    },
                                                                                ],
                                    }
                            ]
                        )
                        
                        try:
                            response = client.update_security_group_rule_descriptions_ingress(
                            GroupId=sg_id,
                            IpPermissions=[
                                {
                                    'FromPort': from_port,
                                                                                'IpProtocol': ip_protocol,
                                                                                'IpRanges': [
                                                                                    {
                                                                                        'CidrIp': cidr_ip,
                                                                                        'Description': 'prod'
                                                                                    },
                                                                                ],
                                    'ToPort': to_port
                                    }
                            ]
                        )
                        except:
                            print('An error occurred while changing this rule description', emoji.emojize(':no_entry:'))


#delete_tmp_sg_ingress(security_group)
change_tag_from_sg(security_group)

print('All clear, check the output to see if there was any errors in the script execution ',
      emoji.emojize(':winking_face:'))
