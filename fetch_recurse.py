#!/usr/bin/env python
# This will query the dns-archiver http interface in
# a recursive manner. For every QUESTION all answers 
# for that question are fetched. For every answer for 
# that question the questions seen for that answer 
# are fetched and displayed.
import os, sys
import urllib
import urllib2

def fetch_data(url):
    req = urllib2.urlopen(url)
    return req.read().split('\n')

if __name__ == '__main__':
    try:
        archive_server = sys.argv[1]
    except:
        print "Usage: %s <archive server:port>"
        sys.exit(1)

    question_url = 'http://%s/questions' % archive_server 
    questions = fetch_data(question_url)

    for question in questions:
        print question
        answer_url = 'http://%s/answers?q=%s' % (archive_server, question)
        answers    = fetch_data(answer_url)   

        for answer in answers:
            print "    %s" % answer
            reverse_ans_url = 'http://%s/answers?q=%s' % (archive_server, answer)
            reverse_ans     = fetch_data(reverse_ans_url)

            for reverse in reverse_ans:
                print "      %s" % reverse
        
        


    
    
