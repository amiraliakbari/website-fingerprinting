# -*- coding: utf-8 -*-
import copy

import MySQLdb as mdb

from Datastore import Datastore
from Packet import Packet
from config import website_clusters, cluster_distances, load_website_clusters, MYSQL_USER, MYSQL_PASSWD
from countermeasure import CounterMeasure


class SmartMorphing(CounterMeasure):
    DEFAULT_PARAMS = {
        'CLUSTER_COUNT': 10,              # Total number of clusters
        'SECTION_COUNT': 10,              # Number of sections to divide traces into (#percentils)
        'D': 7,                           # For selecting target cluster
        'alpha': .01,                     # For calculating split metric, determining the impact of bandwidth
        'BANDWIDTH_D_FACTOR': 25,         # For converting D to bandwidth overhead threshold (D2)
        'MIN_JACCARD_SIMILARITY': 0.7,    # Copying extra dst packets (even in case of size overhead) until output
                                          #   reaches this similarity of dst
        'CLUSTERING_ALGORITHM': 'PAM10',  # MBC9, PAM10, SOM10
        'TIMING_METHOD': 'DST',           # MIN or DST
        'DEFAULT_PAUSE': 1,               # if timing method is not decisive
    }

    def __init__(self, *args, **kwargs):
        super(SmartMorphing, self).__init__(*args, **kwargs)
        self.D = self.D2 = 0
        self.update_params()
        self.dst_trace = None
        self.conn = mdb.connect('localhost', MYSQL_USER, MYSQL_PASSWD, 'Harrmann')
        self.cur = None

    def update_params(self):
        self.D = self.params['D']
        self.D2 = 100 + self.D * self.params['BANDWIDTH_D_FACTOR']

    def apply(self):
        # print 'applying countermeasure'
        if self.dst_trace is None:
            if self.cur is None:
                self.cur = self.conn.cursor()
            alg = self.params['CLUSTERING_ALGORITHM']
            # print('WEBPAGE', int(self.trace.webpage))
            self.cur.execute('SELECT MBC9, PAM10, SOM10 FROM ClustTable WHERE site_id=%s', [int(self.trace.webpage)])
            site_row = self.cur.fetchone()
            if site_row is None:
                print '[ERROR] webpage#{} not found in DB, assuming src_cluster 1.'.format(int(self.trace.webpage))
                src_clust = 1
            else:
                src_clust = int(round(site_row[{'MBC9':0,'PAM10':1,'SOM10':2}[alg]], 0))
            # print('SRC-CLUST', src_clust)
            dst_clust = cluster_distances[src_clust][self.D - 1]
            # print('DST-CLUST', dst_clust)
            self.cur.execute('SELECT site_id FROM ClustTable WHERE {}=%s ORDER BY RAND() LIMIT 1'.format(alg), (dst_clust,))
            selected_site_id = int(round(self.cur.fetchone()[0], 0))
            # print('SELECTED-SITE', selected_site_id)
            sample_trace = Datastore.get_trace(site_id=selected_site_id)
            # print sample_trace
            self.dst_trace = sample_trace

        # print self.trace.get_sizes_str()
        # print self.dst_trace.get_sizes_str()
        print 'Morphing: {} -> {}'.format(self.trace, self.dst_trace)
        self.morph_trace(self.trace, self.dst_trace)
        # print self.new_trace.get_sizes_str()
        # print ''

    def morph_trace(self, src_trace, dst_trace):
        trace_up = self.morph_trace_one_way(src_trace.filter_direction(Packet.UP),
                                            dst_trace.filter_direction(Packet.UP))
        self.morph_trace_one_way(src_trace.filter_direction(Packet.DOWN),
                                 dst_trace.filter_direction(Packet.DOWN))
        for p in trace_up.packets:  # trace_down is already in self.new_trace
            self.add_packet(p)
        self.new_trace.webpage = self.trace.webpage

    def morph_trace_one_way(self, src_trace, dst_trace):
        self.build_new_trace()
        dst_n = len(dst_trace.packets)
        src_n = len(src_trace.packets)
        snapshot = {
            'src': None,
            'dst': None,
        }
        head = {
            'src': 0,
            'dst': 0,
            'src-ended': src_n == 0,
            'dst-ended': dst_n == 0,
            'dst-timing': self.params['DEFAULT_PAUSE'],
            'src-timing': self.params['DEFAULT_PAUSE'],
            'dst-prev': None,
            'src-prev': None,
            'src-size': 0,
        }

        def pop_src_packet():
            # print 'SRC'
            pst = head['src-prev'][1] if head['src-prev'] else None
            ssd, sst, ssl = src_trace.packets[head['src']].get_details()
            head['src-size'] += ssl
            head['src-timing'] = (sst - pst) if pst else self.params['DEFAULT_PAUSE']
            head['src-prev'] = ssd, sst, ssl

            head['src'] += 1
            if head['src'] >= src_n:
                head['src-ended'] = True
            return ssd, sst, ssl

        def pop_dst_packet():
            # print 'DST'
            snapshot['dst'] = copy.copy(head)
            pdt = head['dst-prev'][1] if head['dst-prev'] else None
            ddd, ddt, ddl = dst_trace.packets[head['dst']].get_details()
            head['dst-timing'] = (ddt - pdt) if pdt else self.params['DEFAULT_PAUSE']
            head['dst-prev'] = ddd, ddt, ddl

            head['dst'] += 1
            if head['dst'] >= dst_n:
                head['dst-ended'] = True
                head['dst'] %= dst_n
                sh = dst_trace.packets[dst_n - 1].time + self.params['DEFAULT_PAUSE'] - dst_trace.packets[0].time
                for p in dst_trace.packets:
                    p.time += sh
            return ddd, ddt, ddl

        def put_back_dst_packet():
            if head['dst'] == 0:
                return  # ignoring when the head is rotated
            for k, v in snapshot['dst'].items():
                if k.startswith('dst'):
                    head[k] = v

        def size_overhead_reached():
            ovp = self.get_new_trace_size() * 100.0 / (head['src-size'] or 1)
            return ovp > self.D2

        def get_jaccard_similarity(elems=False):
            return self.jaccard_similarity(map(Packet.getLength, self.new_trace.packets), map(Packet.getLength, dst_trace.packets),
                                           elems=elems)

        def print_overhead_report():
            jc = get_jaccard_similarity()
            ovp = self.get_new_trace_size() * 100.0 / (head['src-size'] or 1)
            ovps = '{0:.0f}%'.format(ovp)
            jcs = '{0:.2f}'.format(jc)
            if ovp > self.D2:
                ovps += ' +++'
            m = jc + ovp / (100.0 * self.D)
            ms = '{0:.4f}'.format(m)
            print head['src-size'], self.get_new_trace_size(), jcs, ovps, ms

        if dst_n == 0:
            print('[WARN] empty dst trace, skipping morphing.')
            for p in src_trace.packets:
                self.add_packet(p)
            return self.new_trace

        while not head['src-ended']:
            # print_overhead_report()
            sd, st, sl = pop_src_packet()
            dd, dt, dl = pop_dst_packet()
            if self.params['TIMING_METHOD'] == 'DST':
                send_time = dt if self.params['TIMING_METHOD'] == 'DST' else st
                send_time = max(st, send_time)  # can not send a packet before it is produced
            elif self.params['TIMING_METHOD'] == 'MIN':
                if st > self.get_new_trace_time():
                    send_time = st
                else:
                    send_time = st + min(head['src-timing'], head['dst-timing'])
            self.add_packet(Packet(sd, send_time, dl))
            if sl > dl:
                remaining = sl - dl
                while remaining > 0:
                    dd, dt, dl = pop_dst_packet()
                    if self.params['TIMING_METHOD'] == 'DST':
                        if dt > st:
                            send_time = dt
                        else:
                            send_time = st + head['dst-timing']
                    elif self.params['TIMING_METHOD'] == 'MIN':
                        send_time = st + min(head['src-timing'], head['dst-timing'])

                    if dl > remaining:
                        # only checking split condition for the last part of a packet
                        a, b = get_jaccard_similarity(elems=True)
                        delta = dl - remaining
                        morph_metric_ov = (a/b) - ((a+1) / (b+1)) + (self.params['alpha'] * delta / self.D)
                        keep_metric_ov = (a/b) - (a / (b + 2))
                        # print '{}/{}'.format(dl, remaining), '+-', morph_metric_ov, keep_metric_ov
                        use_dst_packet = morph_metric_ov <= keep_metric_ov
                        if not use_dst_packet:
                            dl = remaining
                            put_back_dst_packet()

                    self.add_packet(Packet(sd, send_time, dl))
                    remaining -= dl

        while not head['dst-ended']:
            # print_overhead_report()
            if size_overhead_reached():  # we only break if we have *passed* the overhead threshold
                if get_jaccard_similarity() >= self.params['MIN_JACCARD_SIMILARITY']:
                    break
            dd, dt, dl = pop_dst_packet()
            self.add_packet(Packet(dd, dt, dl))

        return self.new_trace

    def get_target_cluster(self):
        website_id = 1  # self.trace.getId().?
        return self.get_website_cluster(website_id)

    @classmethod
    def calc_manhattan_distance(cls, a, b):
        d = 0
        i = 0
        na = len(a)
        nb = len(b)
        while i < min(na, nb):
            d += abs(a[i] - b[i])
            i += 1
        while i < na:
            d += abs(a[i])
            i += 1
        while i < nb:
            d += abs(b[i])
            i += 1
        return d

    @classmethod
    def jaccard_similarity(cls, a, b, elems=False):
        """ Calculate Jaccard Similarity Index for given lists (lists are interpreted as sets)

            :type a: list
            :type b: list
            :return: float
        """
        a = set(a)
        b = set(b)
        n = len(a & b) * 1.0
        d = len(a | b) or 1
        if elems:
            return n, d
        return n / d

    @classmethod
    def get_website_cluster(cls, website_id):
        return website_clusters.get(website_id, 1)

    @classmethod
    def initialize(cls):
        load_website_clusters()

    @classmethod
    def get_name(cls):
        return 'Smart Morphing'
