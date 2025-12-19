# NovaFeed-Python Docker セットアップガイド

このドキュメントは、NovaFeed-PythonをDockerを使用して実行するための完全なセットアップガイドです。

## 前提条件

- [Docker](https://docs.docker.com/get-docker/) (20.10以上)
- [Docker Compose](https://docs.docker.com/compose/install/) (2.0以上)
- git

## クイックスタート

### 1. リポジトリのクローン

```bash
git clone https://github.com/yunfie-twitter/NovaFeed-Python.git
cd NovaFeed-Python
```

### 2. 環境変数ファイルの設定

```bash
cp .env.example .env
```

### 3. Dockerコンテナの起動

```bash
docker-compose up -d
```

### 4. データベースマイグレーション

初回起動時のみ:

```bash
docker-compose exec web python manage.py migrate
```

### 5. スーパーユーザーの作成

```bash
docker-compose exec web python manage.py createsuperuser
```

### 6. アプリケーションへのアクセス

- Webアプリケーション: http://localhost:8000
- Django Admin: http://localhost:8000/admin
- Redis: localhost:6379
- PostgreSQL: localhost:5432

## よく使うコマンド

### コンテナの起動

```bash
# バックグラウンドで起動
docker-compose up -d

# ログを表示して起動
docker-compose up
```

### コンテナの停止

```bash
docker-compose down
```

### ログの確認

```bash
# すべてのサービスのログ
docker-compose logs

# 特定のサービスのログ
docker-compose logs web

# リアルタイムログ
docker-compose logs -f web
```

### Django管理コマンドの実行

```bash
# マイグレーション
docker-compose exec web python manage.py migrate

# マイグレーションの作成
docker-compose exec web python manage.py makemigrations

# 静的ファイルの収集
docker-compose exec web python manage.py collectstatic

# Shellの起動
docker-compose exec web python manage.py shell
```

### コンテナへのアクセス

```bash
# Webコンテナのシェルにアクセス
docker-compose exec web bash

# データベースコンテナのシェルにアクセス
docker-compose exec db psql -U novafeed_user -d novafeed
```

### 完全なリセット

```bash
# すべてのコンテナ、ボリューム、ネットワークを削除
docker-compose down -v

# 再度起動
docker-compose up -d
```

## ボリューム管理

`docker-compose.yml`で定義されているボリューム:

- `postgres_data`: PostgreSQLのデータベースファイル
- `static_volume`: Django静的ファイル
- `media_volume`: ユーザーがアップロードしたメディアファイル

ボリュームの確認:

```bash
docker volume ls | grep novafeed
```

## データベースの管理

### PostgreSQLコンテナに接続

```bash
docker-compose exec db psql -U novafeed_user -d novafeed
```

### バックアップの作成

```bash
docker-compose exec db pg_dump -U novafeed_user -d novafeed > backup.sql
```

### バックアップのリストア

```bash
docker-compose exec -T db psql -U novafeed_user -d novafeed < backup.sql
```

## 本番環境への対応

### 重要なセキュリティ設定

`.env`ファイルで本番環境用に以下を設定:

```env
# セキュリティ
DEBUG=False
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True

# 新しいシークレットキーに変更
SECRET_KEY=<生成した新しいキー>

# ホスト設定
ALLOWED_HOSTS=example.com,www.example.com
```

### 本番環境用Dockerfileの最適化

GunicornやNginxを使用した本番環境構成が必要な場合は、別のDockerfileを作成してください:

```dockerfile
# Dockerfile.prod
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir gunicorn

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "enova_id.wsgi:application", "--bind", "0.0.0.0:8000"]
```

## トラブルシューティング

### ポートが既に使用されている

```bash
# 別のポートにマップ
docker-compose -f docker-compose.yml up -d

# docker-compose.ymlを編集して、ポートマッピングを変更
# ports:
#   - "8001:8000"  # 8001を使用
```

### データベース接続エラー

データベースサービスが起動するまで待機:

```bash
# ヘルスチェックの確認
docker-compose ps

# db の STATUS が "healthy" になるまで待つ
```

### 権限エラー

LinuxでDockerコマンドが失敗する場合:

```bash
sudo usermod -aG docker $USER
# ターミナルを再起動
```

### キャッシュのクリア

```bash
# Redisのフラッシュ
docker-compose exec redis redis-cli FLUSHALL
```

## ネットワーク設定

DjangoコンテナからPostgreSQLコンテナへのアクセス:

- ホスト: `db` (Docker Compose内部ドメイン名)
- ポート: `5432`
- ユーザー: `novafeed_user`
- パスワード: `novafeed_password`
- データベース: `novafeed`

## 更新とアップグレード

### 依存関係の更新

```bash
# Dockerイメージの再ビルド
docker-compose up -d --build
```

### Pythonパッケージの更新

```bash
# requirements.txtを編集してから
docker-compose up -d --build
```

## リソース管理

### ディスク領域の確認

```bash
# Dockerが使用しているディスク領域
docker system df

# 不要なイメージ/コンテナの削除
docker system prune -a
```

### メモリリミットの設定

`docker-compose.yml`で:

```yaml
services:
  web:
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

## 参考リンク

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Django Documentation](https://docs.djangoproject.com/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)

## サポート

問題が発生した場合は、以下を確認してください:

1. ログの確認: `docker-compose logs web`
2. コンテナのステータス: `docker-compose ps`
3. ネットワークの確認: `docker network ls`

---

**最終更新**: 2025-12-20
**バージョン**: 1.0
