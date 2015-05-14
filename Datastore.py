# This is a Python framework to compliment "Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail".
# Copyright (C) 2012  Kevin P. Dyer (kpdyer.com)
# See LICENSE for more details.

import MySQLdb
import math
import config
import pcapparser

from Webpage import Webpage
from Trace import Trace
from Packet import Packet

import memcache
mc = memcache.Client(['127.0.0.1:11211'], debug=0)
ENABLE_CACHE = False

import cPickle

class Datastore:
    conn = None

    @staticmethod
    def getWebpagesLL( webpageIds, traceIndexStart, traceIndexEnd ):
        webpages = []
        for webpageId in webpageIds:
            webpage = Webpage(webpageId)
            for traceIndex in range(traceIndexStart, traceIndexEnd):
                trace = Datastore.getTraceLL( webpageId, traceIndex )
                webpage.addTrace(trace)
            webpages.append(webpage)

        return webpages

    @staticmethod
    def getTraceLL( webpageId, traceIndex ):
        key = '.'.join(['Webpage',
                        'LL',
                        str(webpageId),
                        str(traceIndex)])

        trace = mc.get(key)
        if ENABLE_CACHE and trace:
            trace = cPickle.loads(trace)
        else:
            dateTime = config.DATA_SET[traceIndex]
            trace = pcapparser.readfile(dateTime['month'],
                                        dateTime['day'],
                                        dateTime['hour'],
                                        webpageId)

            mc.set(key,cPickle.dumps(trace,protocol=cPickle.HIGHEST_PROTOCOL))

        return trace

    @staticmethod
    def getWebpagesHerrmann( webpageIds, traceIndexStart, traceIndexEnd ):
        webpages = []
        for webpageId in webpageIds:
            webpage = Webpage(webpageId)
            for traceIndex in range(traceIndexStart, traceIndexEnd):
                trace = Datastore.getTraceHerrmann( webpageId, traceIndex )
                webpage.addTrace(trace)
            webpages.append(webpage)

        return webpages

    @staticmethod
    def getTraceHerrmann( webpageId, traceIndex ):
        if config.DATA_SOURCE == 1:
            datasourceId = 4
        elif config.DATA_SOURCE == 2:
            datasourceId = 5

        key = '.'.join(['Webpage',
                        'H',
                        str(datasourceId),
                        str(webpageId),
                        str(traceIndex)])

        trace = mc.get(key)
        if ENABLE_CACHE and trace:
            trace = cPickle.loads(trace)
        else:
            connection = MySQLdb.connect(host=config.MYSQL_HOST,
                                         user=config.MYSQL_USER,
                                         passwd=config.MYSQL_PASSWD,
                                         db=config.MYSQL_DB )

            cursor = connection.cursor()
            command = """SELECT packets.trace_id,
                                      packets.size,
                                      ROUND(packets.abstime*1000)
                                 FROM (SELECT id
                                         FROM traces
                                        WHERE site_id = (SELECT id
                                                           FROM sites
                                                          WHERE dataset_id = """+str(datasourceId)+"""
                                                          ORDER BY id
                                                          LIMIT """+str(webpageId)+""",1)
                                        ORDER BY id
                                        LIMIT """+str(traceIndex)+""",1) traces,
                                      packets
                                WHERE traces.id = packets.trace_id
                                ORDER BY packets.trace_id, packets.abstime"""
            cursor.execute( command )

            data = cursor.fetchall()
            trace = Trace(webpageId)
            for item in data:
                trace.setId(int(item[0]))
                direction = Packet.UP
                if int(item[1])>0:
                    direction = Packet.DOWN
                time   = item[2]
                length = int(math.fabs(item[1]))

                trace.addPacket( Packet( direction, time, length ) )
            connection.close()

            mc.set(key,cPickle.dumps(trace,protocol=cPickle.HIGHEST_PROTOCOL))

        return trace

    @classmethod
    def get_trace(cls, trace_id=None, site_id=None, dataset=2, limit=1, multi=False):
        if cls.conn is None:
            cls.conn = MySQLdb.connect(host=config.MYSQL_HOST,
                                       user=config.MYSQL_USER,
                                       passwd=config.MYSQL_PASSWD,
                                       db=config.MYSQL_DB)
        cur = cls.conn.cursor()
        if trace_id is None:
            cur.execute('SELECT id FROM traces where site_id=%s ORDER BY RAND() LIMIT {}'.format(limit), [site_id])
            if limit == 1:
                trace_ids = [cur.fetchone()[0]]
            else:
                trace_ids = [r[0] for r in cur.fetchall()]
        else:
            trace_ids = [trace_id]
        # print('SEL-TRACE', trace_ids)

        traces = []
        for trace_id in trace_ids:
            cur.execute('SELECT size, ROUND(abstime*1000) FROM packets WHERE trace_id=%s ORDER BY abstime',
                        [trace_id])
            data = cur.fetchall()
            trace = Trace(trace_id, webpage=site_id)
            for item in data:
                direction = Packet.UP
                if int(item[0]) > 0:
                    direction = Packet.DOWN
                time = item[1]
                length = int(math.fabs(item[0]))
                trace.addPacket(Packet(direction, time, length))
            traces.append(trace)

        if limit == 1 and not multi:
            return traces[0] if traces else None
        return traces
