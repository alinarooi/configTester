name: Test & Update Server List

on:
  schedule:
    - cron: "0 * * * *"
  workflow_dispatch: {}

jobs:
  test-and-update:
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install SSTP client
        run: |
          sudo apt-get update
          sudo apt-get install -y sstp-client ppp
          sstpc --version
          pppd --version

      - name: Download Xray-core
        run: |
          curl -fL -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
          unzip -o xray.zip -d xray-bin
          chmod +x xray-bin/xray
          xray-bin/xray version

      - name: Run tester
        env:
          CF_ALL_URL: ${{ secrets.CF_ALL_URL }}
          CF_UPDATE_URL: ${{ secrets.CF_UPDATE_URL }}
          GH_RAW_URL: "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt"
          XRAY_BIN: ${{ github.workspace }}/xray-bin/xray
          MAX_CANDIDATES: "2000"
          CONCURRENCY: "60"
          MIN_KEEP_RATIO: "0.5"
          MAX_SSTP_CANDIDATES: "2000"
          SSTP_CONCURRENCY: "1"
          SSTP_REAL_TUNNEL: "1"
          SSTP_USERNAME: "vpn"
          SSTP_PASSWORD: "vpn"
          SSTP_TIMEOUT_MS: "30000"
          SSTP_DEBUG: "1"
        run: node scripts/test-and-update-servers.mjs
