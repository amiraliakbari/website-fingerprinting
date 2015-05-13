"""
 This is a Python framework to compliment "Peek-a-Boo, I Still See You: Why
    Efficient Traffic Analysis Countermeasures Fail".

  Copyright (C) 2012  Kevin P. Dyer (http://kpdyer.com)
  See LICENSE for more details.
"""

from __future__ import print_function

import sys
import time
import os
import random
import getopt
import string
import itertools

import MySQLdb as mdb

import config

from Datastore import Datastore

from DirectTargetSampling import DirectTargetSampling
from WrightStyleMorphing import WrightStyleMorphing

# classifiers
from LiberatoreClassifier import LiberatoreClassifier
from WrightClassifier import WrightClassifier
from BandwidthClassifier import BandwidthClassifier
from HerrmannClassifier import HerrmannClassifier
from TimeClassifier import TimeClassifier
from PanchenkoClassifier import PanchenkoClassifier
from VNGPlusPlusClassifier import VNGPlusPlusClassifier
from VNGClassifier import VNGClassifier
from JaccardClassifier import JaccardClassifier
from ESORICSClassifier import ESORICSClassifier
from countermeasure import CounterMeasure


def int_to_countermeasure(n):
    try:
        return config.get_available_countermeasures()[n]
    except KeyError:
        print('[Error] Invalid countermeasure id: {}'.format(n))
        sys.exit(3)


def int_to_classifier(n):
    classifier = None
    if n == config.LIBERATORE_CLASSIFIER:
        classifier = LiberatoreClassifier
    elif n == config.WRIGHT_CLASSIFIER:
        classifier = WrightClassifier
    elif n == config.BANDWIDTH_CLASSIFIER:
        classifier = BandwidthClassifier
    elif n == config.HERRMANN_CLASSIFIER:
        classifier = HerrmannClassifier
    elif n == config.TIME_CLASSIFIER:
        classifier = TimeClassifier
    elif n == config.PANCHENKO_CLASSIFIER:
        classifier = PanchenkoClassifier
    elif n == config.VNG_PLUS_PLUS_CLASSIFIER:
        classifier = VNGPlusPlusClassifier
    elif n == config.VNG_CLASSIFIER:
        classifier = VNGClassifier
    elif n == config.JACCARD_CLASSIFIER:
        classifier = JaccardClassifier
    elif n == config.ESORICS_CLASSIFIER:
        classifier = ESORICSClassifier

    return classifier


def usage():
    print("""
    -N [int] : use [int] websites from the dataset
               from which we will use to sample a privacy
               set k in each experiment (default 775)

    -k [int] : the size of the privacy set (default 2)

    -d [int]: dataset to use
        0: Liberatore and Levine Dataset (OpenSSH)
        1: Herrmann et al. Dataset (OpenSSH)
        2: Herrmann et al. Dataset (Tor)
        (default 1)

    -C [int] : classifier to run
        0: Liberatore Classifer
        1: Wright et al. Classifier
        2: Jaccard Classifier
        3: Panchenko et al. Classifier
        5: Lu et al. Edit Distance Classifier
        6: Herrmann et al. Classifier
        4: Dyer et al. Bandwidth (BW) Classifier
        10: Dyer et al. Time Classifier
        14: Dyer et al. Variable n-gram (VNG) Classifier
        15: Dyer et al. VNG++ Classifier
        (default 0)

    -c [int]: countermeasure to use
        0: None (default)
        1: Pad to MTU
        2: Session Random 255
        3: Packet Random 255
        4: Pad Random MTU
        5: Exponential Pad
        6: Linear Pad
        7: Mice-Elephants Pad
        8: Direct Target Sampling
        9: Traffic Morphing
        10: BuFLO
        11: Tamaraw
        12: SmartMorphing

    -n [int]: number of trials to run per experiment (default 1)

    -t [int]: number of training traces to use per experiment (default 16)

    -T [int]: number of testing traces to use per experiment (default 4)
    """)


def info(*args):
    print('[INFO]', *args)


def error(*args, **kwargs):
    ex = kwargs.pop('exit', None)
    print('[ERROR]', *args)
    if ex is not None:
        sys.exit(ex)


calc_overhead = lambda n, o: ('{}/{}'.format(n, o), ((n * 1.0 / o) - 1) * 100)


def read_arguments():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:T:N:k:c:C:d:n:r:h:p:P")
    except getopt.GetoptError, err:
        print(str(err))  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    char_set = string.ascii_lowercase + string.digits
    run_id = ''.join(random.sample(char_set, 8))
    countermeasure_params = ''
    classifier_params = ''

    for o, a in opts:
        if o == "-k":
            config.BUCKET_SIZE = int(a)
        elif o == "-C":
            config.CLASSIFIER = int(a)
        elif o == "-d":
            config.DATA_SOURCE = int(a)
        elif o == "-c":
            config.COUNTERMEASURE = int(a)
        elif o == "-N":
            config.TOP_N = int(a)
        elif o == "-t":
            config.NUM_TRAINING_TRACES = int(a)
        elif o == "-T":
            config.NUM_TESTING_TRACES = int(a)
        elif o == "-n":
            config.NUM_TRIALS = int(a)
        elif o == "-r":
            run_id = str(a)
        elif o == "-P":
            classifier_params = str(a)
        elif o == "-p":
            countermeasure_params = str(a)
        else:
            usage()
            sys.exit(2)

    return run_id, countermeasure_params, classifier_params

def set_params(obj, params_str):
    params = params_str.split(',')
    for p in params:
        if not p or not p.strip():
            continue
        try:
            attr, val = p.strip().split('=', 1)
        except ValueError:
            error('Invalid parameter:', p)
            return 3
        try:
            val = int(val)
        except ValueError:
            pass
        obj.set_param(attr, val)

def run_morphing():
    run_id, countermeasure_params, classifier_params = read_arguments()

    # Selecting Algorithms
    classifier = int_to_classifier(config.CLASSIFIER)
    countermeasure = int_to_countermeasure(config.COUNTERMEASURE)
    classifier_name = classifier.__name__ if classifier else 'None'
    countermeasure_name = countermeasure.__name__ if countermeasure else 'None'
    countermeasure.initialize()
    countermeasure = countermeasure()
    set_params(countermeasure, countermeasure_params)

    # Run
    for run_index in range(config.NUM_TRIALS):
        run_start_time = time.time()
        print('Run #{}'.format(run_index))

        # Selecting Sample Webpages
        src_clust = 4
        d = 7
        k = config.BUCKET_SIZE
        alg = 'PAM10'
        dst_clust = config.cluster_distances[src_clust][d - 1]
        print('cluster: {} -> {}'.format(src_clust, dst_clust))
        conn = mdb.connect('localhost', config.MYSQL_USER, config.MYSQL_PASSWD, 'Harrmann')
        cur = conn.cursor()
        cur.execute('SELECT site_id FROM ClustTable WHERE {}=%s ORDER BY RAND() LIMIT 1'.format(alg), (dst_clust,))
        D_site = cur.fetchone()[0]
        web_pages = [D_site]
        cur.execute('SELECT site_id FROM ClustTable WHERE {}=%s ORDER BY RAND() LIMIT {}'.format(alg, k-1), (src_clust,))
        for s in cur.fetchall():
            web_pages.append(s[0])
        print('Webpages:', web_pages)

        traces = []
        for wp in web_pages:
            t = Datastore.get_trace(site_id=wp)
            traces.append(t)

        rl = {'size': 0, 'time': 0}
        ov = {'size': 0, 'time': 0}

        D_trace = None
        training = []
        testing = []
        for trace in traces:
            if trace.webpage != D_site:
                training.append([trace, trace.webpage])

            if trace.webpage == D_site:
                testing.append([trace, D_site])
                D_trace = trace
            else:
                countermeasure.dst_trace = D_trace
                morphed = countermeasure.apply_to_trace(trace)
                testing.append([morphed, trace.webpage])
                rl['size'] += trace.getBandwidth()
                ov['size'] += morphed.getBandwidth()

        print('Overhead:\n\tsize: {}, {:.0f}%\n\ttime: N/A'.format(*calc_overhead(ov['size'], rl['size'])))


def run():
    run_id, countermeasure_params, classifier_params = read_arguments()

    output_filename_list = [
        'results',
        'k' + str(config.BUCKET_SIZE),
        'c' + str(config.COUNTERMEASURE),
        'd' + str(config.DATA_SOURCE),
        'C' + str(config.CLASSIFIER),
        'N' + str(config.TOP_N),
        't' + str(config.NUM_TRAINING_TRACES),
        'T' + str(config.NUM_TESTING_TRACES),
    ]
    output_filename = os.path.join(config.OUTPUT_DIR, '.'.join(output_filename_list))

    if not os.path.exists(config.CACHE_DIR):
        os.mkdir(config.CACHE_DIR)

    if not os.path.exists(output_filename + '.output'):
        banner = ['accuracy', 'overhead', 'timeElapsedTotal', 'timeElapsedClassifier']
        f = open(output_filename + '.output', 'w')
        f.write(','.join(banner))
        f.close()
    if not os.path.exists(output_filename + '.debug'):
        f = open(output_filename + '.debug', 'w')
        f.close()

    # Data-set Selection
    training_set_size = config.NUM_TRAINING_TRACES
    testing_set_size = config.NUM_TESTING_TRACES
    if config.DATA_SOURCE == 0:
        dataset_size = len(config.DATA_SET)
        start_index = config.NUM_TRAINING_TRACES
        end_index = len(config.DATA_SET) - config.NUM_TESTING_TRACES
    elif config.DATA_SOURCE == 1:
        dataset_size = 160
        max_traces_per_website_h = 160
        start_index = config.NUM_TRAINING_TRACES
        end_index = max_traces_per_website_h - config.NUM_TESTING_TRACES
    elif config.DATA_SOURCE == 2:
        dataset_size = 18
        max_traces_per_website_h = 18
        start_index = config.NUM_TRAINING_TRACES
        end_index = max_traces_per_website_h - config.NUM_TESTING_TRACES
    else:
        error('Invalid data-source id:', config.DATA_SOURCE)
        return 3

    # Checking Training-set and Test-set Sizes
    info('|dataset|={}\t|training-set|={}, |testing-set|={}'.format(dataset_size, training_set_size, testing_set_size))
    if training_set_size + testing_set_size > dataset_size:
        print('[ERROR] t+T is larger than data-set size!')
        print('\tThe data-set is divided into two parts: Training set (t) and Testing set (T), so t+T must be ')
        print('\tless than or equal to the total number of data in data-set.')
        sys.exit(4)

    # Selecting Algorithms
    classifier = int_to_classifier(config.CLASSIFIER)
    countermeasure = int_to_countermeasure(config.COUNTERMEASURE)
    classifier_name = classifier.__name__ if classifier else 'None'
    countermeasure_name = countermeasure.__name__ if countermeasure else 'None'
    if issubclass(countermeasure, CounterMeasure):
        countermeasure.initialize()
        countermeasure = countermeasure()  # also instantiating
        new_style_cm = True
    else:
        new_style_cm = False
    countermeasure_params = countermeasure_params.split(',')
    for p in countermeasure_params:
        if not p or not p.strip():
            continue
        try:
            attr, val = p.strip().split('=', 1)
        except ValueError:
            error('Invalid parameter:', p)
            return 3
        try:
            val = int(val)
        except ValueError:
            pass
        if new_style_cm:
            countermeasure.set_param(attr, val)
        else:
            setattr(countermeasure, attr, val)

    # Run
    for run_index in range(config.NUM_TRIALS):
        run_start_time = time.time()
        print('Run #{}'.format(run_index))

        # Select a sample of size k from websites 1..N
        webpage_ids = range(0, config.TOP_N - 1)
        random.shuffle(webpage_ids)
        webpage_ids = webpage_ids[0:config.BUCKET_SIZE]
        seed = random.randint(start_index, end_index)
        info('selected webpages:', webpage_ids)

        training_set = []
        testing_set = []
        target_webpage = None

        actual_bandwidth = 0
        modified_bandwidth = 0
        actual_timing = 0
        modified_timing = 0

        for page_id in webpage_ids:
            print('.', end='')
            sys.stdout.flush()

            # Sampling From Data-source
            if config.DATA_SOURCE == 0:
                webpage_train = Datastore.getWebpagesLL([page_id], seed - config.NUM_TRAINING_TRACES, seed)
                webpage_test = Datastore.getWebpagesLL([page_id], seed, seed + config.NUM_TESTING_TRACES)
            elif config.DATA_SOURCE in [1, 2]:
                webpage_train = Datastore.getWebpagesHerrmann([page_id], seed - config.NUM_TRAINING_TRACES, seed)
                webpage_test = Datastore.getWebpagesHerrmann([page_id], seed, seed + config.NUM_TESTING_TRACES)
            else:
                error('Invalid data-source id:', config.DATA_SOURCE)
                return 3

            # Selecting Targets
            webpage_train = webpage_train[0]
            webpage_test = webpage_test[0]
            if target_webpage is None:
                target_webpage = webpage_train
            print(webpage_test, webpage_train)

            # Accounting
            actual_bandwidth += webpage_train.getBandwidth()
            actual_bandwidth += webpage_test.getBandwidth()

            # Train Countermeasure
            metadata = None
            if new_style_cm:
                countermeasure.train(src_page=webpage_train, target_page=target_webpage)
            else:
                if countermeasure in [DirectTargetSampling, WrightStyleMorphing]:
                    metadata = countermeasure.buildMetadata(webpage_train, target_webpage)

            # Applying Countermeasure (and feeding data to classifier)
            for i, w in enumerate([webpage_train, webpage_test]):
                for trace in w.getTraces():
                    actual_timing += trace.get_total_time()
                    # print(trace.get_total_time(), '-', end='')

                    if countermeasure:
                        if new_style_cm:
                            modified_trace = countermeasure.apply_to_trace(trace)
                        else:
                            if countermeasure in [DirectTargetSampling, WrightStyleMorphing]:
                                if w.getId() != target_webpage.getId():
                                    modified_trace = countermeasure.applyCountermeasure(trace, metadata)
                                else:
                                    modified_trace = trace
                            else:
                                modified_trace = countermeasure.applyCountermeasure(trace)
                    else:
                        modified_trace = trace

                    # Overhead Accounting
                    modified_bandwidth += modified_trace.getBandwidth()
                    modified_timing += modified_trace.get_total_time()
                    # print(modified_trace.get_total_time())

                    instance = classifier.traceToInstance(modified_trace)
                    if instance:
                        if i == 0:  # train-page
                            training_set.append(instance)
                        elif i == 1:  # test-page
                            testing_set.append(instance)

        # Classification
        print('')
        classification_start_time = time.time()
        [accuracy, debug_info] = classifier.classify(run_id, training_set, testing_set)
        run_end_time = time.time()

        # Write Output
        overhead, overhead_ratio = calc_overhead(modified_bandwidth, actual_bandwidth)
        overhead_t, overhead_ratio_t = calc_overhead(modified_timing, actual_timing)
        run_total_time = run_end_time - run_start_time
        classification_total_time = run_end_time - classification_start_time
        output = [accuracy, overhead, '%.2f' % run_total_time, '%.2f' % classification_total_time]
        summary = ', '.join(itertools.imap(str, output))
        f = open(output_filename + '.output', 'a')
        f.write('\n' + summary)
        f.close()

        # Processing Classification Results For Each Page
        sites_detected = []
        sites_not_detected = []
        f = open(output_filename + '.debug', 'a')
        for entry in debug_info:
            if entry[0] == entry[1]:
                sites_detected.append(entry[0])
            else:
                sites_not_detected.append(entry[0])
            f.write(entry[0] + ',' + entry[1] + '\n')
        f.close()

        # Show A Brief Report To User
        info('sites detected correctly:\t{}'.format(', '.join(sites_detected)))
        info('sites detected incorrectly:\t{}'.format(', '.join(sites_not_detected)))
        info('Run summary: ({}, {})'.format(classifier_name, countermeasure_name))
        info('\taccuracy:\t{}%'.format(accuracy))
        info('\toverhead:\t{} bytes ({:.1f}%), {} ms ({:.1f}%)'.format(overhead, overhead_ratio, overhead_t, overhead_ratio_t))
        info('\tduration:\t{:.1f}s'.format(run_total_time))

    return 0


if __name__ == '__main__':
    sys.exit(run_morphing() or 0)
