#!/usr/bin/env python3
import abc
import json
import re
from math import sqrt
import logging 
from config import UPDATE_FREQUENCY, HALSEY_API_URL
from utils import loge, logi
import time
import requests
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

class GigiAgent(object):

    TOGGLE = HALSEY_API_URL + "/vnet/toggle"
    STATS = HALSEY_API_URL + "/sim/attack"
    QOS = HALSEY_API_URL + "/sim/qos"
    HIST = HALSEY_API_URL + "/ids/hist"
    VNET = HALSEY_API_URL + "/vnet/get?host=" 

    IDS_DELTA_THRESHOLD = 1
    QOS_THRESHOLD = 0.0

    def __init__(self, h1_ip, h2_ip):
        super().__init__()
        self.last_ids_cid = 0
        self.last_ips_cid = 0
        self.h1_history = []
        self.h2_history = []
        self.h1_ip = h1_ip
        self.h2_ip = h2_ip

    def iter(self):
        pass

    def _vnet(self, mac): 
        r = requests.get(GigiAgent.VNET + mac)
        r.raise_for_status()
        return json.loads(r.text)

    def start(self):
        try:
            while True:
                logi("Agent run")
                self.iter()
                time.sleep(UPDATE_FREQUENCY)
        except KeyboardInterrupt:
            loge("Quitting.")
            exit(0)

    def _fetch_hist(self, net):
        time.sleep(5) 
        r = requests.get(GigiAgent.HIST + "?net=" + net + "&interval=5")
        r.raise_for_status()
        return json.loads(r.text)

    def _fetch_qos(self):
        r = requests.get(GigiAgent.QOS)
        r.raise_for_status()
        return json.loads(r.text)

    @property
    def _h1_ip(self):
        return self.h1_ip

    @property
    def _h2_ip(self):
        return self.h2_ip

    def _is_hist_down(self, hist):
        if len(hist) == 0:
        #    print ("0= down") 
            return 0
        
        
        avg = lambda l: sum(l)/len(l)
        sd = lambda l: sqrt(avg([x**2 for x in l]) - avg(l)**2)

        print (avg(hist)) 
 #       iman_bs_var = (hist[-1] - avg(hist)) / sd(hist) 
#        print (iman_bs_var) 
        return avg(hist) #(hist[-1] - avg(hist)) / sd(hist) < GigiAgent.IDS_DELTA_THRESHOLD

    def _qos_index(self, info_dict):
        return float(info_dict["insight"])

    def is_qos_good(self, qos):
        return qos >= GigiAgent.QOS_THRESHOLD

    def _fetch_attack_stats(self):
        """
        Cycles through hosts and If the host is an attacker instance
        or what we call a malicious host then it reports back on the
        failures/successes of the attack or in other words if the
        attack is being suppressed in anyway.
        """
        r = requests.get(GigiAgent.STATS)
        r.raise_for_status()
        return json.loads(r.text)

    def toggle(self, hostmac):
        """
        Moves a host from low security to high security
        and vice versa
        """
        r = requests.get(GigiAgent.TOGGLE + "?host=" + hostmac)
        r.raise_for_status()
        return 1

    def _get_ids_ips_occurrences(self, net):
        """
        Reads IPS alerts/logs from a SQL DB running connected in real time
        to the logs from the IPS deployed on the VN Benign
        Return 0 if up for h1 and h2
        Return 1 if up for h1 and down for h2
        Return 2 if down for h1 and up for h2
        Return 3 if down  for h1 and h2
        """
        hist = self._fetch_hist(net)
        #print ("hist= ")
        #print(hist) 
                
        h1_hist = [d["frequency"] for d in hist if self.h1_ip in d.values()]
        h2_hist = [d["frequency"] for d in hist if self.h2_ip in d.values()]
        print(net) 
        #print ("h1 hist= ")
        #print(h1_hist)
        #print ("h2 hist= ")
        #print( h2_hist)
        #print (self.h1_ip) 
        h1up =0 
        h2up=0
        time.sleep(5) 
        
        f_hist= self._fetch_hist(net) 
        f_h1_hist = [d["frequency"] for d in f_hist if self.h1_ip in d.values()]
        f_h2_hist = [d["frequency"] for d in f_hist if self.h2_ip in d.values()]

        print ("h1 & h2 avgs" ) 
        h1avg = self._is_hist_down(h1_hist) 
        print ("-") 
        h2avg = self._is_hist_down(h2_hist) 
        
        print("f_h1 & f_h2 avgs - f is 5 seconds after non f") 
        f_h1avg = self._is_hist_down(f_h1_hist) 
        print ("-") 
        f_h2avg = self._is_hist_down(f_h2_hist) 




        if (h1avg > 2 ):#and f_h1avg >= h1avg): 
            h1up =1
        if (h2avg > 5):# and f_h2avg >= h2avg):
            h2up =1

#        print (h1up) 
#        print( h2up ) 
        
        if (h1up ==1 and h2up ==1):
            return 0 
        if (h1up ==1 and h2up ==0): 
            return 1 
        if (h1up==0 and h2up ==0): 
            return 3 
        return 2 
        #return 0 #int(self._is_hist_down(h1_hist)) * 1 + \
               #int(self._is_hist_down(h2_hist) * 2)

    def get_ids_ips_occurrences(self):
        #return self._get_ids_ips_occurrences("ids"), self._get_ids_ips_occurrences("ips")
        x=  int(self._vnet("0a:a5:a2:89:82:60")["net"][4]) , int(self._vnet("6e:9e:36:73:3b:10")["net"][4] )
        ## VNet 2 is IPS VNET 1 is IDS 
        ## h1 , h2 | 1 = IDS ,2 =  IPS 
        if (x == (2,2)):  
            return 3,0 

        if (x == (2,1)):  
            return 2,1

        if (x == (1,1)):  
            return 0,3
        if (x == (1,2)):  
            return 1,2
        print (x)  
        return 0,0 
    def get_reward(self):
        """
        Reads QOS metrics for hosts and returns a score
        Gives a score [-1,+1] that shows better score
        for better QOS on h2 (benging) and worse on h1 (malicious)
            # 1 for h2 QOS good and h1 QOS bad
            # -0.3 for QOS bad for both or QOS good for both
            #-1 for h1 QOS good and h2 QOS bad
        """
        qos_data = self._fetch_qos()
        attack_data = self._fetch_attack_stats()
        

        avg = lambda l: sum(l) / len(l)
        nw_score = lambda l: avg([self._qos_index(d) for d in l])
        failrate = lambda stat: re.match(r"failure rate\s*=\s*(.+)", stat).group(1).replace(",", ".")
       # iman_sucks = scipy.stats.hmean(failrate(d["stats"]) for d in attack_data) 
        
        
        # 8==D step one: attack prevention rate := 1 - attack success rate => p1, p2, p3, ...
        # 8==D step two: normalize QoS to a reasonable range => q1, q2, q3, ...
        # 8==D step three: reward = hmean(p1, ..., q1, ...)
        
        
        
        print (qos_data)
        print("===============")                               

        attack_score = avg([float(failrate(d["stats"])) for d in attack_data])
        print(attack_score) 
        scale = lambda x: -1 + 1.3 * (x+1)


        return scale(nw_score(qos_data["benign"]) - nw_score(qos_data["malicious"]) + 1.6 * attack_score)


if __name__ == "__main__":
    agent = GigiAgent("210.0.0.101", "210.0.0.102")
    agent.get_reward() 
#    h = agent._fetch_hist("ids") 
#    print (h) 
#   print( agent.get_ids_ips_occurrences())
    #print ("=================== TOGGLE H1 ==============") 
    #agent.toggle("0a:a5:a2:89:82:60")
    #print ("=================== TOGGLE DONE ==============") 
    #time.sleep(5) 
    #agent.get_ids_ips_occurrences()
