.class public Lcom/fieldsync/net/ApiClient;
.super Ljava/lang/Object;

# Decompiled Dalvik bytecode (baksmali). The const-string ops below reveal a
# backend credential and a basic-auth fallback that shipped in the release APK.
.field private static final BASE_URL:Ljava/lang/String; = "https://api.fieldsync.example.com"

.method static constructor <clinit>()V
    .registers 2
    const-string v0, "x-api-key"
    const-string v1, "wkUq8ZpL3nRtY6vB9mCfX2sH5dJ4gK7a"
    return-void
.end method

.method public buildFallbackUri()Ljava/lang/String;
    .registers 2
    const-string v0, "https://svc:S3rv1ceAcct@api.fieldsync.example.com/v1"
    return-object v0
.end method
