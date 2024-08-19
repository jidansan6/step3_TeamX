# 2024.08.18 初期作成 TOKKY

# 必要なライブラリのimport
from fastapi import FastAPI, Depends, HTTPException
from typing import Optional, List
from pydantic import BaseModel
import uuid, json, math
import bcrypt
from datetime import datetime
import pytz

# SQL用
import mysql.connector
from mysql.connector import Error

# env読み込み用
import os
from os.path import join, dirname
from dotenv import load_dotenv

# 環境変数envファイルからの取得用
load_dotenv(verbose=True)
dotenv_path = join(dirname(__file__), ".env")
load_dotenv(dotenv_path)


########################### FOR LOGIN ################################
# login認証
class AuthInfo(BaseModel):
    password: str
    email: str


# ユーザー登録
class UserregInfo(BaseModel):
    last_name: str
    first_name: str
    last_name_kana: str
    first_name_kana: str
    email: str
    phone_number: str
    password: str


# ユーザーのログイン後情報
class UserInfo(BaseModel):
    user_id: str
    service_id: str


######################################################################


app = FastAPI()
# ターミナルでuvicorn main:app --reload（mainはファイル名）


# CORS設定 #############################################################
from fastapi.middleware.cors import CORSMiddleware

origins = [
    "http://localhost:3000",  # フロントエンドのオリジン
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
########################################################################

# 環境変数の取得
host = os.environ.get("host")
database_username = os.environ.get("database_username")
database_password = os.environ.get("database_password")
ssl_ca = "DigiCertGlobalRootCA.crt.pem"


########################################################################
# 関数
########################################################################
# タイムゾーン変更 ######################################################
def convert_utc_to_jst(utc_datetime):
    jst = pytz.timezone("Asia/Tokyo")
    jst_datetime = utc_datetime.astimezone(jst)
    return jst_datetime


# Password #############################################################
# パスワードをハッシュ化する関数
def hash_password(password):
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    hashed_str = hashed.decode("utf-8")
    return hashed_str


# パスワードが一致するか確認する関数
def check_password(stored_hash, password):
    stored_hash_bytes = stored_hash.encode("utf-8")
    password_bytes = password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, stored_hash_bytes)


# DB接続 & Login ########################################################
# データベース接続を取得する関数
def get_db_connection():
    db_config = {
        "user": database_username,
        "password": database_password,
        "host": host,
        "database": "teamxdata",
        "ssl_ca": ssl_ca,
    }
    conn = mysql.connector.connect(**db_config)
    return conn


# ユーザー認証関数
def authenticate_user(email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    # ユーザーの情報を取得するクエリ
    query = "SELECT password_hash FROM Users WHERE email = %s"
    try:
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        # ユーザーが存在しない場合
        if result is None:
            print("User not found.")
            return False
        stored_hash = result[0]
        # パスワードの照合
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
            print("Authentication successful.")
            userdata = get_userdata(email)
            return userdata
        else:
            print("Authentication failed.")
            return False
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return False
    finally:
        cursor.close()
        conn.close()


# DB書き込み #############################################################
# ユーザー追加
def add_user(
    last_name,
    first_name,
    last_name_kana,
    first_name_kana,
    email,
    phone_number,
    password,
):
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = hash_password(password)
    user_id = str(uuid.uuid4())  # user_idをここで生成
    # 新規ユーザークエリ
    query = """
    INSERT INTO Users (
        user_id, last_name, first_name, last_name_kana, first_name_kana, email, phone_number, password_hash
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    try:
        # クエリの実行
        cursor.execute(
            query,
            (
                user_id,
                last_name,
                first_name,
                last_name_kana,
                first_name_kana,
                email,
                phone_number,
                password_hash,
            ),
        )
        conn.commit()
        print("User added successfully.")
        return {"message": "User registered successfully.", "user_id": user_id}
    except mysql.connector.Error as err:
        # エラーコード 1062 は重複エントリ（Duplicate entry）、同じメアドの登録を防ぐ
        if err.errno == 1062:
            print(f"{email} は既に登録されています。メールアドレスを確認してください。")
            return {"message": f"{email} は既に登録されています。", "user_id": None}
        else:
            print(f"Database error: {err}")
            return {"message": f"{email} は既に登録されています。", "user_id": None}
    finally:
        cursor.close()
        conn.close()


# DB読みだし #############################################################
# ユーザーIDのみの取得
def get_userdata(email):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM Users WHERE email = %s"
    try:
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        if result is None:
            print("No service found with the provided ID.")
            return None
        return result
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# サービスIDに基づいてサービス情報を取得する関数
def get_service_by_id(service_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM Services WHERE service_id = %s"
    try:
        cursor.execute(query, (service_id,))
        result = cursor.fetchone()
        if result is None:
            print("No service found with the provided ID.")
            return None
        for key, value in result.items():
            if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                result[key] = convert_utc_to_jst(value)
        return result
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# ステータスIDから詳細を引き出すコード
def get_status_with_service_name(status_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = """
    SELECT 
        s.status_name, 
        s.start_date, 
        s.end_date, 
        s.service_id, 
        sv.service_name
    FROM 
        Status s
    JOIN 
        Services sv ON s.service_id = sv.service_id
    WHERE 
        s.status_id = %s
    """
    try:
        # クエリの実行
        cursor.execute(query, (status_id,))
        result = cursor.fetchone()
        if result is None:
            print("No status found with the provided ID.")
            return None
        for key, value in result.items():
            if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                result[key] = convert_utc_to_jst(value)
        return result
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# UserIDから、各サービスの登録状況及びステータス情報を取得するコード
def get_user_registrations_with_status(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = """
    SELECT 
        ur.registration_id, 
        ur.user_id, 
        ur.service_id, 
        ur.status_level, 
        ur.status_id, 
        s.status_name, 
        s.start_date, 
        s.end_date, 
        sv.service_name
    FROM 
        UserRegistrations ur
    LEFT JOIN 
        Status s ON ur.status_id = s.status_id
    LEFT JOIN 
        Services sv ON ur.service_id = sv.service_id
    WHERE 
        ur.user_id = %s
    """
    try:
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        # 各行に対してループ処理
        for row in results:
            for key, value in row.items():
                if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                    row[key] = convert_utc_to_jst(value)
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# コンテンツの引き出し
def get_content_by_service_id(service_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = """
    SELECT 
        content_id, 
        service_id, 
        content_name, 
        content_url, 
        category, 
        duration 
    FROM 
        Content 
    WHERE 
        service_id = %s
    """
    try:
        cursor.execute(query, (service_id,))
        results = cursor.fetchall()
        if not results:
            print("No content found for the provided service ID.")
            return None
        # durationを分に変換
        for row in results:
            if "duration" in row and row["duration"] is not None:
                row["duration"] = stom(row["duration"])
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 自分が所属する班の名前と、所属メンバーの情報を収集
def get_group_members_excluding_self(service_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = """
    SELECT 
        gn.group_id,        -- group_idを選択
        gn.group_name, 
        CONCAT(u.last_name, u.first_name) AS full_name
    FROM 
        GroupMembers gm
    JOIN 
        GroupNames gn ON gm.group_id = gn.group_id
    JOIN 
        Users u ON gm.user_id = u.user_id
    WHERE 
        gn.service_id = %s AND gm.user_id != %s AND gm.group_id IN (
            SELECT group_id FROM GroupMembers WHERE user_id = %s
        )
    """
    try:
        cursor.execute(query, (service_id, user_id, user_id))
        results = cursor.fetchall()
        if not results:
            print("No group members found for the provided service ID and user ID.")
            return None
        # 結果をグループごとにまとめる
        group_data = {}
        for result in results:
            group_id = result["group_id"]  # group_idを取得
            group_name = result["group_name"]
            full_name = result["full_name"]
            if group_id not in group_data:
                group_data[group_id] = {
                    "group_id": group_id,
                    "group_name": group_name,
                    "full_name": [],
                }
            group_data[group_id]["full_name"].append(full_name)

        return list(group_data.values())
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 過去の講義動画を一括取得
def get_videos_by_service_id(service_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    query = """
    SELECT 
        video_id, 
        video_title, 
        video_link, 
        attachment_1_link, 
        attachment_2_link, 
        attachment_3_link, 
        attachment_4_link, 
        attachment_5_link, 
        created_at, 
        last_updated
    FROM 
        PastVideos 
    WHERE 
        service_id = %s
    """
    try:
        cursor.execute(query, (service_id,))
        results = cursor.fetchall()
        if not results:
            print("No videos found for the provided service ID.")
            return None
        # 各行に対してループ処理
        for row in results:
            for key, value in row.items():
                if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                    row[key] = convert_utc_to_jst(value)
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 自分にアサインされた動画を取得（前処理としてグループIDからビデオリスト取得）
def get_video_ids_by_group_id(group_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # 自班IDに紐づいた動画のIDを取得するクエリ
    query = """
    SELECT 
        video_id 
    FROM 
        VideoDistribution 
    WHERE 
        group_id = %s
    """
    try:
        cursor.execute(query, (group_id,))
        results = cursor.fetchall()

        if not results:
            print("No videos found for the provided group ID.")
            return None
        # 結果をリストとして返す
        video_ids = [row[0] for row in results]
        return video_ids
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 自分にアサインされた動画を取得（後処理）
def get_videos_by_video_ids(video_ids):
    if not video_ids:
        return None
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # 結果を辞書形式で取得
    # 複数の動画IDに対応する動画情報を取得するクエリ
    query = """
    SELECT 
        video_id, 
        video_title, 
        video_link, 
        attachment_1_link, 
        attachment_2_link, 
        attachment_3_link, 
        attachment_4_link, 
        attachment_5_link, 
        created_at, 
        last_updated
    FROM 
        PastVideos 
    WHERE 
        video_id IN (%s)
    """ % ",".join(
        ["%s"] * len(video_ids)
    )
    try:
        cursor.execute(query, tuple(video_ids))
        results = cursor.fetchall()

        if not results:
            print("No videos found for the provided video IDs.")
            return {"video_id": None}
        # 各行に対してループ処理
        for row in results:
            for key, value in row.items():
                if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                    row[key] = convert_utc_to_jst(value)
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 自班に紐づいた宿題を取得するコード
def get_assignments_by_group_id(group_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # 自班IDに紐づいた宿題を取得するクエリ
    query = """
    SELECT 
        assignment_id,
        content_id,
        assignment_name,
        deadline,
        description,
        url,
        notes,
        required,
        duration
    FROM 
        Assignments 
    WHERE 
        group_id = %s
    """
    try:
        cursor.execute(query, (group_id,))
        results = cursor.fetchall()
        if not results:
            print("No assignments found for the provided group ID.")
            return None
        # 各行に対してループ処理
        for row in results:
            for key, value in row.items():
                if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                    row[key] = convert_utc_to_jst(value)
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 宿題の詳細を取得するコード
def get_content_details_by_content_id(content_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # content_id に紐づくコンテンツの詳細を取得するクエリ
    query = """
    SELECT 
        content_id,
        service_id,
        content_name,
        content_url,
        category,
        duration
    FROM 
        Content 
    WHERE 
        content_id = %s
    """
    try:
        cursor.execute(query, (content_id,))
        result = cursor.fetchone()
        if not result:
            print(f"No content found for content_id {content_id}.")
            return None
        for key, value in result.items():
            if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                result[key] = convert_utc_to_jst(value)
        return result
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 班に紐づいた宿題を取得→詳細取得を一気に処理する
def get_assignments_with_content_details(group_id):
    assignments = get_assignments_by_group_id(group_id)
    if not assignments:
        return json.dumps([])  # 空のリストを返す
    detailed_assignments = []
    for assignment in assignments:
        content_details = get_content_details_by_content_id(assignment["content_id"])
        if content_details:
            assignment["content_details"] = content_details
        detailed_assignments.append(assignment)
    return detailed_assignments


# 期限を過ぎていない宿題の取得
def get_assignments_by_group_id_deadline(group_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # 自班IDに紐づいた、かつ期限が過ぎていない宿題を取得するクエリ
    query = """
    SELECT 
        assignment_id,
        content_id,
        assignment_name,
        deadline,
        description,
        url,
        notes,
        required,
        duration
    FROM 
        Assignments 
    WHERE 
        group_id = %s AND (deadline >= NOW() OR deadline IS NULL)
    """
    try:
        cursor.execute(query, (group_id,))
        results = cursor.fetchall()

        if not results:
            print("No assignments found for the provided group ID.")
            return None
        # 各行に対してループ処理
        for row in results:
            for key, value in row.items():
                if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                    row[key] = convert_utc_to_jst(value)
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 【期限がまだすぎていないもので、】班に紐づいた宿題を取得→詳細取得を一気に処理する
def get_assignments_with_content_details_deadline(group_id):
    assignments = get_assignments_by_group_id_deadline(group_id)
    if not assignments:
        return json.dumps([])  # 空のリストを返す
    detailed_assignments = []
    for assignment in assignments:
        content_details = get_content_details_by_content_id(assignment["content_id"])
        if content_details:
            assignment["content_details"] = content_details
        detailed_assignments.append(assignment)
    return detailed_assignments


# イベント情報の取得
def get_events_by_service_id(service_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # 結果を辞書形式で取得

    # サービスIDに基づいて全イベント情報を取得するクエリ
    query = """
    SELECT 
        event_id,
        service_id,
        title,
        event_datetime,
        location,
        description,
        notes,
        created_at,
        last_updated
    FROM 
        EventCalendar 
    WHERE 
        service_id = %s
    """

    try:
        cursor.execute(query, (service_id,))
        results = cursor.fetchall()

        if not results:
            print("No events found for the provided service ID.")
            return None
            # 各行に対してループ処理
        for row in results:
            for key, value in row.items():
                if isinstance(value, datetime):  # 日付時刻の場合のみ変換
                    row[key] = convert_utc_to_jst(value)
        return results

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None
    finally:
        cursor.close()
        conn.close()


# 結果をJSON形式に変換する関数 ############################################
def convert_result_to_json(result):
    if result:
        json_output = json.dumps(result, default=str, ensure_ascii=False, indent=4)
        return json_output
    else:
        return json.dumps({})


# 秒数をだいたいの分数に切り上げ処理 #######################################
def stom(seconds):
    minutes = math.ceil(seconds / 60)
    return str(minutes)


#########################################################################
# 下記インスタンス
#########################################################################
# login処理＆Trueで個人情報取得
@app.post("/login")
def login(authinfo: AuthInfo):
    res = authenticate_user(authinfo.email, authinfo.password)
    return res


# 新規ユーザー登録
@app.post("/register")
def register(userreginfo: UserregInfo):
    res = add_user(
        userreginfo.last_name,
        userreginfo.first_name,
        userreginfo.last_name_kana,
        userreginfo.first_name_kana,
        userreginfo.email,
        userreginfo.phone_number,
        userreginfo.password,
    )
    return res


# ステータスIDで詳細を取得
@app.get("/getstatus/{id}")
def getstatus(id: str):
    res = get_status_with_service_name(id)
    return res


# ユーザーIDでユーザーの登録状況およびステータスの取得
@app.get("/getuserstatus/{id}")
def getuserstatus(id: str):
    res = get_user_registrations_with_status(id)
    return res


# サービスIDでコンテンツを全件取得
@app.get("/getcontents/{id}")
def getcontents(id: str):
    res = get_content_by_service_id(id)
    return res


# サービスIDと顧客IDの組合わせで所属する班の名前と所属班員を収集
@app.post("/mygroup")
def mygroup(userinfo: UserInfo):
    res = get_group_members_excluding_self(userinfo.service_id, userinfo.user_id)
    return res


# サービスIDで過去動画コンテンツを全件取得
@app.get("/getlecturedata/{id}")
def getlecturedata(id: str):
    res = get_videos_by_service_id(id)
    return res


# グループIDで自分にアサインされた動画を取得
@app.get("/getmylecture/{id}")
def getmylecture(id: str):
    video_ids = get_video_ids_by_group_id(id)
    if video_ids:
        result = get_videos_by_video_ids(video_ids)
        return result
    else:
        return {"video_id": None}


# 自班に紐づいた宿題を全取得
@app.get("/getmyassignment/{id}")
def getmyassignment(id: str):
    res = get_assignments_with_content_details(id)
    return res


# 自班に紐づいた宿題を全取得
@app.get("/getmyassignment-deadline/{id}")
def getmyassignment_deadline(id: str):
    res = get_assignments_with_content_details_deadline(id)
    return res


# サービスIDに紐づいたイベントを全取得
@app.get("/geteventdate/{id}")
def get_events_by_service_id(id: str):
    res = get_assignments_with_content_details_deadline(id)
    return res
