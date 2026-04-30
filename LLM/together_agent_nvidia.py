import requests
from process_htmls import fetch_ripestat_prefix_html, fetch_ripestat_asn_html, build_prompt
import json
from get_caida_data import get_relationship, get_relationship_dict, get_caida_rels
from rpki_validator import validate_prefix_asn, extract_roa_asns
from load_ihr_hegemony import get_heg_dependency
from gemini_agent import analyze_with_gemini
#from ollama_agent import analyze_with_ollama_model
from nvidia_agent import analyze_with_ChatOpenAI_model
import pickle
from datetime import datetime
import os
import json
import csv
import shaman_data_process_lib
import as_relationship
from preload_RIPEstat_data import _load_json, _save_json
from fix_json_str import extract_and_fix_json

#from extract_json import extract_origin_conflict_routes



TOGETHER_API_KEY = "tgp_v1_8Y3DAJ-NGohHEvtH2rgCu6j5rSeGU6-Da84EQs6BKtM"
TOGETHER_URL = "https://api.together.xyz/v1/chat/completions"




def analyze_with_together(context, query):
    template = f"""
You are a BGP routing analyst. Use the following context to address the tasks:

Context:
{context}

Tasks:
{query}

Answer:
"""

    payload = {
        #"model": "mistralai/Mixtral-8x7B-Instruct-v0.1",
        
        "model": "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
        "temperature": 0.6,
        "messages": [
            {"role": "user", "content": template}
        ]
    }
    
    
    headers = {
        "Authorization": f"Bearer {TOGETHER_API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post(TOGETHER_URL, headers=headers, json=payload)
    response_json = response.json()
    
    if "choices" in response_json:
        return response_json["choices"][0]["message"]["content"]
    else:
        print("Error or unexpected responses!")
        return response_json

def examine_invalid_routes():
    origin_conflicting_routes = list()
    with open("invalid_routes_list_large_new.json", "r") as file:
        invalid_routes = json.load(file)
        for route in invalid_routes:
            prefix = route['prefix']
            origin_asn = route['origin_as']
            rpki_data = validate_prefix_asn(prefix, origin_asn)
            
            if rpki_data.get("validated_route", {}).get("validity", {}).get("state", "unknown") == "invalid":
            #if rpki_data.get("validated_route", {}).get("validity", {}).get('description', '') == 'At least one VRP Covers the Route Prefix, but no VRP ASN matches the route origin ASN':
                origin_conflicting_routes.append(route)
                
    return origin_conflicting_routes


# Step 2: function to append a JSON object
def write_json_to_csv(json_obj, csv_file, fieldnames=None):
    # If fieldnames not given, use keys from this object
    if fieldnames is None:
        fieldnames = list(json_obj.keys())

    with open(csv_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        # write header if file is empty
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow({k: json_obj.get(k, "") for k in fieldnames})

    
    
def together_agent():
    #{'timestamp': '2025-05-31 00:35:01', 'prefix': '41.87.31.0/24', 'as_path': (49673, 3216, 6453, 6762, 30844, 36969), 'origin_as': 36969}
    #Possible as path manipulation: [49673, 20485, 6762, 17494, 150748, 150748, 139026, 23923, 23923] 23923 is announcing a prefix authorized by 139026.
    
    #when using shaman's data:
    data_file = "./shaman/real_hijacks_2024.csv"
    origin_conflicting_routes = shaman_data_process_lib.extract_invalid_routes(data_file)
    
    
    #Otherwise:
    #origin_conflicting_routes = examine_invalid_routes()
    label = "nvidia"
    model_name = label + "/Llama-3.1-Nemotron-70B-Instruct-HF"   
    
    # CSV file path
    csv_file = "./new_results/origin_conflicts/2024/"+label+"_reasoning_origin_conflicting_routes.txt"
    
    # Ensure CSV file exists with headers even if program crashes
    with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
        pass
        
    #num = 0
    all_relationships = get_relationship_dict()
    response = None
    prefix_cache_file = "./cache/RIPEstat_prefix_cache.json"
    asn_cache_file = "./cache/RIPEstat_asn_cache.json"
    
    prefix_cache = _load_json(prefix_cache_file)
    asn_cache = _load_json(asn_cache_file)
    
    for i in range(0, len(origin_conflicting_routes)):
        try:
            timestamp = origin_conflicting_routes[i]['timestamp']
            prefix = origin_conflicting_routes[i]['prefix']
            origin_asn = origin_conflicting_routes[i]['origin_as']
            #as_path = list(origin_conflicting_routes[i]['as_path'])
            as_path = "Not available"
            
            rpki_data = validate_prefix_asn(prefix, origin_asn)
            
            rpki_validation_output, roa_asns = extract_roa_asns(rpki_data)
            #get_relationship(origin_asn, roa_asn)
            
            caida_data = get_caida_rels(origin_asn, all_relationships)
            
            #hege_data = get_heg_dependency(origin_asn, roa_asns, timestamp) # Hegemony data can support the Caida data as there are possible errors in caida data.
            hege_data = None
            
            rpki_json = json.dumps(rpki_data)
            #caida_json = json.dumps(caida_data)
            
            #if no existing data, then using http requests
            
            entry = prefix_cache.setdefault(prefix, {})
            # Fetch prefix info if missing
            entry["RIPEstat_prefix_json"] = entry.get("RIPEstat_prefix_json") or fetch_ripestat_prefix_html(prefix)
            RIPEstat_prefix_json = entry["RIPEstat_prefix_json"]
            
            entry = asn_cache.setdefault(origin_asn, {})
            # Fetch ASN info if missing
            entry["RIPEstat_origin_asn_json"] = entry.get("RIPEstat_origin_asn_json") or fetch_ripestat_asn_html(origin_asn)
            RIPEstat_origin_asn_json = entry["RIPEstat_origin_asn_json"]
            
            caida_as_rel = ""
            RIPEstat_roas_asn_lists = []
            for roa_asn in roa_asns:
                entry = asn_cache.setdefault(roa_asn, {})
                entry["RIPEstat_origin_asn_json"] = entry.get("RIPEstat_origin_asn_json") or fetch_ripestat_asn_html(roa_asn)
                RIPEstat_roas_asn_lists.append(entry["RIPEstat_origin_asn_json"])
                
                rel = as_relationship.get_relationship(origin_asn, roa_asn, caida_data)
                if rel != "none" and rel != "unknown":
                    caida_as_rel = caida_as_rel + f"The authorized AS in the ROA (AS{roa_asn}) is a {rel} of the origin AS in the announcement (AS{origin_asn}). "
                
            RIPEstat_roas_asn_json = json.dumps(RIPEstat_roas_asn_lists)
            
            #_save_json(prefix_cache_file, prefix_cache)
            #_save_json(asn_cache_file, asn_cache)
            
            
            
            
            ##CAIDA AS rank data: {}
            Context = f'''BGP hijacks can be classified into two types: prefix hijacks and subprefix hijacks. RPKI enforces Route Origin Validation (ROV) on BGP announcements to help prevent such hijacks. However, some RPKI-invalid routes result from operator misconfigurations between closely related ASes (e.g., customer–provider or sibling relationships), and are known as benign conflicts.

The closer the AS-level relationship between two conflicting origin ASes, the more likely the route is benign. Based on the provided information, infer the relationship level between the origin AS in the announcement and the authorized AS in the ROA (which represents the legitimate prefix holder).

Consider factors such as economic, policy distance or geographical distance between the two ASes. Then, reevaluate the given RPKI-invalid BGP route and determine whether it represents a genuine hijack or a benign conflict:

                Announcement timestamp: {timestamp}
                
                Prefix: {prefix}

                Origin AS in BGP update: AS{origin_asn}

                AS path: {as_path}

            NOTE: please take care of the announcement timestamp, particularly when analyzing transfer history. If the AS path is not available, please do not assess the path.
            
            Extra information collected for this prefix:

                RPKI route origin validation output: {rpki_validation_output}
                
                CAIDA AS relationship data: {caida_as_rel}
            
                IHR Hegemony (AS dependency) data: {hege_data}
                
                RIPEstat json data of the announced prefix: {RIPEstat_prefix_json}
                
                RIPEstat json data of the origin AS in BGP update: {RIPEstat_origin_asn_json}
                
                '''
                
            if len(roa_asns) == 0:
                Context = Context + ""
            else:
                Context = Context + f"RIPEstat json data of the authorized ASes in ROAs: {RIPEstat_roas_asn_json}"
                
            
            query = """
            
                
                Task: Assess whether an invalid BGP announcement is benign.
               
                

                1. Assign a benign likelihood level:
                   - Low: No relationship or supporting context (i.e., unrelated ASes)
                   - Medium: Some circumstantial evidence but no confirmation
                   - High: Strong evidence of a benign relationship (e.g., same organization, provider-customer)

                2. Explain why the level was assigned.

                3. Suggest a possible reason for the conflict.

                4. Identify contributing factors (multiple allowed):
                   - Prefix Transfer / Ownership Change
                   - Multi-Origin with Partial ROA Coverage
                   - Delegated / Upstream-Downstream Announcements
                   - Traffic Engineering / Deaggregate Mismatches
                   - Third-Party Announcements (CDNs, DDoS mitigation, cloud edges)
                   - Hijacks
                   - Others (only if no reasonable inference can be made)
                 
                  Rules:
                - Select the most plausible factor(s) based on provided data and known operational practices.
                - External operational knowledge may be used.
                - If AS_path is not available; please do not consider it and assign "N/A" in the output.
                - Respond ONLY with a valid JSON format.
                
                Output format:
                {
                  "prefix": "string",
                  "AS_path": "string",
                  "origin_AS": "string",
                  "authorized_ASes_in_ROAs": "string",
                  "benign_level": "High | Medium | Low",
                  "explanation": "string",
                  "possible_reason": "string",
                  "factors": ["string"]
                }
                
                

                
                """
        
            
            #in some case, I did see the origin as is a customer of a major upstream (like a tier1 as)

            #response = analyze_with_together(Context, query)
            #response = analyze_with_gemini(Context, query)
            #print(response)
            
            #model_name = "gemma3:27b"
            #response = analyze_with_ollama_model(model_name, Context, query)
            
            response = analyze_with_ChatOpenAI_model(model_name, Context, query)
            # fix json string
            json_response = extract_and_fix_json(response)
            print(json_response)
            write_json_to_csv(json_response, csv_file, fieldnames=None)
            
            
            
            
            '''
            f.write(response+'\n')
            f.close()
            num = num +1
            '''
            
        except Exception as e:
            print(f"[ERROR] Failed to qwen reasoning: {e}; {response}")
        
        
        
    
    

if __name__ == "__main__":
    
    #print(len(examine_invalid_routes()))
    together_agent()
    
    #Context = extract_origin_conflict_routes()
    #print(len(Context))
    query = '''
    please classify the RPKI-invalid routes included in the Context based on possible root causes. RPKI-invalid routes described individually.

Each route entry includes fields such as:

    prefix

    origin_as

    authorized_as in ROAs

    explanation

    possible_reason. 
    
    
How many routes are there in total? Please answer how many routes involve customer-provider relationship, how many involve the same organizations, how many involve AS dependency, how many involve Transfer/Ownership changes. If a route falls into multiple categores, the counts should be non-exclusive. How many involve traffic engineering?
    
    
    '''
    #response = analyze_with_together(Context, query)
    #print(response)
  
    



