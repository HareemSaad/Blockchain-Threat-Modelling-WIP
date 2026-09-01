// Generates a Threat Dragon v2 WEB3 threat model for an ETH <-> server <-> Arbitrum
// token bridge. Threat text is pulled verbatim from web3.rules.json and category
// display names from en.json, so the model matches the fork's own rules engine.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vueSrc = resolve(__dirname, '../td.vue/src');
const rules = JSON.parse(readFileSync(resolve(vueSrc, 'service/threats/models/web3.rules.json'), 'utf8'));
const en = JSON.parse(readFileSync(resolve(vueSrc, 'i18n/en.json'), 'utf8'));
const web3Names = en.threatmodel ? en.threats.model.web3 : en.threats.model.web3;

// fixed port ids reused per node (as the stock demo models do)
const P = { top: 'p-top', right: 'p-right', bottom: 'p-bottom', left: 'p-left' };
const portAttrs = { circle: { r: 4, magnet: true, stroke: '#5F95FF', strokeWidth: 1, fill: '#fff', style: { visibility: 'hidden' } } };
const ports = () => ({
    groups: {
        top: { position: 'top', attrs: portAttrs },
        right: { position: 'right', attrs: portAttrs },
        bottom: { position: 'bottom', attrs: portAttrs },
        left: { position: 'left', attrs: portAttrs }
    },
    items: [
        { group: 'top', id: P.top },
        { group: 'right', id: P.right },
        { group: 'bottom', id: P.bottom },
        { group: 'left', id: P.left }
    ]
});

let threatCounter = 0;
const mkThreat = (key) => {
    const r = rules[key];
    if (!r) { throw new Error(`unknown rule key: ${key}`); }
    threatCounter += 1;
    return {
        id: `threat-${key}-${threatCounter}`,
        title: r.title,
        status: 'Open',
        severity: r.severity || 'TBD',
        type: web3Names[key],
        description: r.description,
        mitigation: r.mitigation,
        modelType: 'WEB3',
        new: false,
        number: threatCounter,
        score: ''
    };
};

let z = 0;
const node = (shape, dataType, name, x, y, w, h, extraData, threatKeys = []) => {
    const threats = threatKeys.map(mkThreat);
    return {
        position: { x, y },
        size: { width: w, height: h },
        attrs: {
            text: { text: name },
            body: { stroke: '#333333', strokeWidth: 1.5, strokeDasharray: null }
        },
        visible: true,
        shape,
        ports: ports(),
        id: `n-${dataType}-${name}`.replace(/[^a-z0-9-]/gi, '-').toLowerCase(),
        zIndex: (z += 1),
        data: {
            type: dataType,
            name,
            description: '',
            outOfScope: false,
            reasonOutOfScope: '',
            hasOpenThreats: threats.length > 0,
            ...extraData,
            threats
        }
    };
};

const boundaryBox = (name, x, y, w, h) => ({
    position: { x, y },
    size: { width: w, height: h },
    attrs: { label: { text: name } },
    visible: true,
    shape: 'trust-boundary-box',
    id: `bb-${name}`.replace(/[^a-z0-9-]/gi, '-').toLowerCase(),
    zIndex: -1,
    data: { type: 'tm.BoundaryBox', name, description: '', isTrustBoundary: true, hasOpenThreats: false }
});

const textBlock = (text, x, y, w, h) => ({
    position: { x, y },
    size: { width: w, height: h },
    attrs: { text: { text } },
    visible: true,
    shape: 'td-text-block',
    id: `txt-${(z += 1)}`,
    zIndex: 2,
    data: { type: 'tm.Text', name: text, hasOpenThreats: false }
});

const flow = (name, src, srcPort, tgt, tgtPort, opts = {}, threatKeys = []) => {
    const threats = threatKeys.map(mkThreat);
    return {
        shape: 'flow',
        attrs: {
            line: {
                stroke: '#333333',
                targetMarker: { name: 'block' },
                sourceMarker: { name: opts.bidirectional ? 'block' : '' },
                strokeDasharray: null
            }
        },
        width: 200,
        height: 100,
        zIndex: (z += 1),
        labels: [{
            markup: [
                { tagName: 'ellipse', selector: 'labelBody' },
                { tagName: 'text', selector: 'labelText' }
            ],
            attrs: {
                labelText: { text: name, textAnchor: 'middle', textVerticalAnchor: 'middle' },
                labelBody: { ref: 'labelText', refRx: '50%', refRy: '60%', fill: '#fff', strokeWidth: 0 }
            },
            position: { distance: 0.5, args: { keepGradient: true, ensureLegibility: true } }
        }],
        connector: 'smooth',
        data: {
            type: 'tm.Flow',
            name,
            description: '',
            outOfScope: false,
            reasonOutOfScope: '',
            hasOpenThreats: threats.length > 0,
            isBidirectional: !!opts.bidirectional,
            isEncrypted: !!opts.isEncrypted,
            isPublicNetwork: !!opts.isPublicNetwork,
            protocol: opts.protocol || '',
            threats
        },
        id: `flow-${name}`.replace(/[^a-z0-9-]/gi, '-').toLowerCase(),
        source: { cell: src, port: srcPort },
        target: { cell: tgt, port: tgtPort },
        vertices: opts.vertices || []
    };
};

// ---- elements ----
const userWallet = node('actor', 'tm.Actor', 'User Wallet', 40, 300, 150, 80,
    { providesAuthentication: true }, ['wallet', 'signing']);

const ethBridge = node('smart-contract', 'tm.SmartContract', 'ETH Bridge (Lockbox)', 300, 240, 160, 100,
    { isUpgradeable: true, handlesValue: true, usesExternalCalls: true, usesOracle: false },
    ['contractReentrancy', 'contractAccessControl', 'contractUpgradeability', 'bridge']);

const tokenVault = node('smart-contract', 'tm.SmartContract', 'ERC-20 Token Vault', 300, 390, 160, 100,
    { isUpgradeable: false, handlesValue: true, usesExternalCalls: true, usesOracle: false },
    ['contractAccessControl', 'contractUncheckedCall']);

const relayer = node('process', 'tm.Process', 'Relayer / Validator Server', 690, 250, 170, 120,
    { privilegeLevel: 'high' }, ['bridge', 'gasGriefing']);

const signingKey = node('store', 'tm.Store', 'Relayer Signing Key', 700, 430, 160, 80,
    { storesCredentials: true, isEncrypted: false }, ['keyManagement']);

const arbBridge = node('smart-contract', 'tm.SmartContract', 'Arbitrum Bridge', 1050, 240, 160, 100,
    { isUpgradeable: true, handlesValue: true, usesExternalCalls: true, usesOracle: false },
    ['bridge', 'replay', 'contractAccessControl', 'contractReentrancy']);

const minter = node('smart-contract', 'tm.SmartContract', 'Wrapped Token Minter', 1050, 390, 160, 100,
    { isUpgradeable: false, handlesValue: true, usesExternalCalls: false, usesOracle: false },
    ['contractAccessControl', 'contractArithmetic']);

const ethBoundary = boundaryBox('Ethereum L1 (trust boundary)', 250, 180, 360, 340);
const arbBoundary = boundaryBox('Arbitrum L2 (trust boundary)', 1000, 180, 380, 340);
const title = textBlock('Token Bridge: Ethereum <-> Relayer Server <-> Arbitrum\nWEB3 methodology (experience-based)', 40, 40, 520, 60);

// ---- flows ----
const flows = [
    flow('1. Deposit + lock (signed tx)', userWallet.id, P.right, ethBridge.id, P.left,
        { isPublicNetwork: true }, ['signing']),
    flow('lock funds', ethBridge.id, P.bottom, tokenVault.id, P.top, {}, []),
    flow('2. Lock event / attestation', ethBridge.id, P.right, relayer.id, P.left,
        { isPublicNetwork: true, protocol: 'JSON-RPC/WSS' }, ['rpcTransport']),
    flow('signs with', relayer.id, P.bottom, signingKey.id, P.top, {}, []),
    flow('3. Relay message + signature (mint)', relayer.id, P.right, arbBridge.id, P.left,
        { isPublicNetwork: true, protocol: 'JSON-RPC' }, ['replay', 'bridge']),
    flow('mint wrapped token', arbBridge.id, P.bottom, minter.id, P.top, {}, []),
    flow('4. Burn / withdraw event', arbBridge.id, P.top, relayer.id, P.right,
        { isPublicNetwork: true, bidirectional: false, vertices: [{ x: 950, y: 200 }] }, [])
];

const cells = [ethBoundary, arbBoundary, title, userWallet, ethBridge, tokenVault,
    relayer, signingKey, arbBridge, minter, ...flows];

const model = {
    version: '2.4.0',
    summary: {
        title: 'Web3 Token Bridge (Ethereum <-> Arbitrum)',
        owner: 'hareemsaad',
        description: 'Threat model for a cross-chain token bridge: users lock ERC-20 tokens in an Ethereum bridge contract, a relayer/validator server attests the lock and relays a signed message to an Arbitrum bridge contract that mints the wrapped token. Modeled with the experience-based WEB3 methodology.',
        id: 0
    },
    detail: {
        contributors: [{ name: 'hareemsaad' }],
        diagrams: [{
            id: 0,
            title: 'ETH <-> Arbitrum Bridge',
            diagramType: 'WEB3',
            placeholder: 'New Web3 diagram description',
            thumbnail: './public/content/images/thumbnail.jpg',
            version: '2.4.0',
            cells
        }],
        diagramTop: 1,
        reviewer: '',
        threatTop: threatCounter + 1
    }
};

const outPath = resolve(__dirname, '../ThreatDragonModels/web3-bridge-eth-arbitrum.json');
writeFileSync(outPath, JSON.stringify(model, null, 2) + '\n');
console.log(`Wrote ${outPath}`);
console.log(`Cells: ${cells.length}, threats: ${threatCounter}`);
