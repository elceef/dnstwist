#!/usr/bin/python3

from dnstwist import dnstwist
import os
import json
import whois

def compare_domains(old,new,keys):
	# check key existence; if none, fail
	# if new value != new value add a message to updates list
	updates = list()
	if old != new:
		for key in keys:
			if key not in old or key not in new:
				raise KeyError("Missing key in dictionary:",key)
			if old[key] != new[key]:
				updates.append(f"{key} changed from {old[key]}")
	return updates

def set_diff(old,new):
	additions = list(new.difference(old))
	additions.sort()
	subtractions = list(old.difference(new))
	subtractions.sort()
	intersection = list(new.intersection(old))
	intersection.sort()
	return additions, subtractions, intersection

def compareData(old_domains,new_domains,comparison_keys):
	# first handle the origin domains that have been added/removed
	report_list = dict()
	new_origins = set([d for d in new_domains.keys()])
	old_origins = set([d for d in old_domains.keys()])
	origin_additions, origin_subtractions, origin_intersection = set_diff(old_origins,new_origins)
	# add additions
	for d in origin_additions:
		report_list[d] = list(new_domains[d])
	# mark as additions
	for origin_domain in origin_additions:
		for fuzzed in new_domains[origin_domain]:
			fuzzed['action'] = 'added'
	# add subtractions
	for d in origin_subtractions:
		report_list[d] = list(old_domains[d])
	# mark as removals
	for origin_domain in origin_subtractions:
		for fuzzed in old_domains[origin_domain]:
			fuzzed['action'] = 'removed'
	
	# next, handle the intersection
	for origin_domain in origin_intersection:
		# these have been presorted, and sets are unordered so have to create arrays to be able to match index
		# correctly for the dictionary objects that represent the fuzzed domains
		new_domain_names = [d['domain-name'] for d in new_domains[origin_domain]]
		old_domain_names = [d['domain-name'] for d in old_domains[origin_domain]]
		new_fuzz = set(new_domain_names)
		old_fuzz = set(old_domain_names)
		fuzz_additions, fuzz_subtractions, fuzz_intersection = set_diff(old_fuzz,new_fuzz)
		report_list[origin_domain] = list()
		prev_index_new = 0
		prev_index_old = 0
		prev_i_new_intersect = 0
		prev_i_old_intersect = 0

		# additions
		for d in fuzz_additions:
			# search and add to report_list
			index = new_domain_names.index(d,prev_index_new)
			prev_index_new = index
			fuzzed = dict(new_domains[origin_domain][index])
			fuzzed['action'] = 'added'
			report_list[origin_domain].append(fuzzed)

		# subtractions
		for d in fuzz_subtractions:
			# search and add to report_list
			index = old_domain_names.index(d,prev_index_old)
			prev_index_old = index
			fuzzed = dict(old_domains[origin_domain][index])
			fuzzed['action'] = 'removed'
			report_list[origin_domain].append(fuzzed)

		# handle intersection
		for d in fuzz_intersection:
			# get old dict
			old_index = old_domain_names.index(d,prev_i_old_intersect)
			prev_i_old_intersect = old_index
			old_fuzzed = dict(old_domains[origin_domain][old_index])
			# get new dict
			new_index = new_domain_names.index(d,prev_i_new_intersect)
			prev_i_new_intersect = new_index
			new_fuzzed = dict(new_domains[origin_domain][new_index])
			# compare
			updates = compare_domains(old_fuzzed,new_fuzzed,comparison_keys)
			if len(updates):
				fuzzed = dict(new_fuzzed)
				fuzzed['action'] = ",".join(updates)
				report_list[origin_domain].append(fuzzed)
	return report_list


def monitor_domains(domain_list = r"./domains.txt",data_file = r"./domainData.json",
base_options = {"registered":True,"geoip":True,"ssdeep":True,"nameservers":["8.8.8.8","4.4.4.4"],"threadcount":25},
new_origin_options = {}):
	""" This function is meant to monitor domains read from a new line delimited file.
	It will compare against ./domainData.json if it exists, if not results will be written there
	for future comparison. The base_options parameter is passed for all domains that dnstwist is run on.
	It is HIGHLY RECOMMENDED to leave "registered" set to True.
	The new_origin_options holds params that will be passed only to based domains not found in the data_file param.
	The results will be a diff of the data_file and the current run indicating what changed. 
	Return type will be a map with entries from domain_list file as keys and a list the corresponding 
	diffed dnstwist results as the values.
	"""
	fuzzed_domains = dict()
	current_list = dict()
	report_list = dict()
	comparison_keys = ['domain-name','dns-a','dns-aaaa','dns-ns','dns-mx']

	try:
		with open(domain_list,"r") as file:
			domains = [d.rstrip() for d in file.readlines()]
	except FileNotFoundError as err:
		print(err)
		raise

	print("Successfully imported domain monitor list.\nMonitoring {0} domains".format(len(domains)))

	# pulling from google's DNS for the time being
	# get all variations of fuzzed domains
	# if output file doesn't exist or domain not in list, use whois option
	if os.path.exists(data_file):
		with open(data_file,"r") as file:
			current_list = json.load(file)
	print("Successfully loaded previous data for {0} base domains".format(len(current_list.keys())))
	print("Starting domain twisting")
	for domain in domains:
		if domain not in current_list.keys():
			fuzzed_domains[domain] = dnstwist(domain,**new_origin_options,**base_options)
		else:
			fuzzed_domains[domain] = dnstwist(domain,**base_options)
	# alphabetically sort all the fuzzed domain results to simplify comparison
	print("Sorting domain results")
	for _, domain in fuzzed_domains.items():
		domain.sort(key=lambda d: d['domain-name'])

	# if no data file, it's all new
	# otherwise, compare the two lists
	if len(current_list.keys()) == 0:
		print("No previous base domains found. Treating all information as new.")
		report_list = dict(fuzzed_domains)
		for _, origin_domain in report_list.items():
			for domain in origin_domain:
				domain['action'] = 'added'
	else:
		# compare logic adding changed domains with status
		print("Comparing new results against data file...")
		report_list = compareData(current_list,fuzzed_domains,comparison_keys)
		for key, origin_domain in report_list.items():
			# adding this to avoid mass whois lookups; 
			# allows us to multithread the rest of the domain lookups,
			# get only those that are registered,
			# and then to go back for a significantly smaller subset 
			# single threaded for whois to avoid IP blocking
			print("Checking whois information for {0}".format(key))
			for domain in origin_domain:
				try:
					whoisdb = whois.query(domain['domain-name'])
					domain['whois-created'] = str(whoisdb.creation_date).split(' ')[0]
					domain['whois-updated'] = str(whoisdb.last_updated).split(' ')[0]
				except:
					domain['whois-created'] = None
					domain['whois-updated'] = None

	# overwrite the datafile with newest results
	print("Writing new results to data file")
	with open(data_file,"w") as outfile:
		json.dump(fuzzed_domains, outfile)

	#TODO: fire off report by whatever means 
	return report_list

if __name__ == "__main__":
	monitor_domains()