import { v4 as uuidv4 } from 'uuid';

import models from './models/index.js';
import web3Rules from './models/web3.rules.json';
import { isOpen, isResolved } from './status.js';
import { tc } from '../../i18n/index.js';
import store from '@/store/index.js';

// WEB3: default starting category per element, used when no threat-frequency
// rotation is available. The Smart Contract element leads with reentrancy.
const web3DefaultTypeKey = (cellType) => {
    switch (cellType) {
    case 'tm.Actor': return 'wallet';
    case 'tm.Store': return 'keyManagement';
    case 'tm.Process': return 'slippage';
    case 'tm.SmartContract': return 'contractReentrancy';
    case 'tm.Flow':
    default: return 'signing';
    }
};

// WEB3 rules engine: pre-fill an experience-based threat (title, description,
// mitigation, severity) from the rules library, keyed by the category key
// (e.g. 'contractReentrancy'). Mutates and returns the threat. Safe no-op for
// unknown keys. Exported so the suggest dialog can fill per-type suggestions.
export const applyWeb3Rule = function (threat, typeKey) {
    const rule = typeKey && web3Rules[typeKey];
    if (!rule) {
        return threat;
    }
    if (rule.title) { threat.title = rule.title; }
    if (rule.description) { threat.description = rule.description; }
    if (rule.mitigation) { threat.mitigation = rule.mitigation; }
    if (rule.severity) { threat.severity = rule.severity; }
    return threat;
};


const valuesToTranslations = {
    /* CIA */
    Confidentiality: 'threats.model.cia.confidentiality',
    Integrity: 'threats.model.cia.integrity',
    Availability: 'threats.model.cia.availability',
    /* CIADIE */
    Distributed: 'threats.model.die.distributed',
    Immutable: 'threats.model.die.immutable',
    Ephemeral: 'threats.model.die.ephemeral',
    /* LINDDUN */
    Linkability: 'threats.model.linddun.linkability',
    Identifiability: 'threats.model.linddun.identifiability',
    'Non-repudiation': 'threats.model.linddun.nonRepudiation',
    Detectability: 'threats.model.linddun.detectability',
    'Disclosure of information': 'threats.model.linddun.disclosureOfInformation',
    Unawareness: 'threats.model.linddun.unawareness',
    'Non-compliance': 'threats.model.linddun.nonCompliance',
    /**
 * PLOT4ai is intentionally not added here.
 *
 * The current structure doesn´t allow frameworks to have categories with the same name. This is a problem for plot4ai & linddun,
 * because they share two categories with the same name. This functionality is only used in the migration flow from v1->v2
 * and v1 simply didn't store the modelType with the threat - this can therefor not be fixed.
 * The migration-flow has been partially fixed in such a way that the modelType is derived from the diagramType, but it's not certain
 * that this will alway be set, which is why this code is still here.
 * However, since this mapping object seems to be used only for migration and plot4ai didn't exist in version 1,
 * it should not be a problem that plot4ai is not added here
 */
    /* STRIDE */
    Spoofing: 'threats.model.stride.spoofing',
    Tampering: 'threats.model.stride.tampering',
    Repudiation: 'threats.model.stride.repudiation',
    'Information disclosure': 'threats.model.stride.informationDisclosure',
    'Denial of service': 'threats.model.stride.denialOfService',
    'Elevation of privilege': 'threats.model.stride.elevationOfPrivilege',

};

const convertToTranslationString = (val) => valuesToTranslations[val];

export const createNewTypedThreat = function (modelType, cellType, number) {
    let title, type;
    // track the category key chosen so the WEB3 rules engine can look up
    // pre-filled title/description/mitigation/severity below
    let typeKey;

    if (!modelType) {
        modelType = 'STRIDE';
    } else if (modelType.toLowerCase() === 'generic') {
        modelType = 'default';
    } else if (modelType === 'DIE') {
        modelType = 'CIADIE';
    }
    title = tc(`threats.generic.${modelType.toLowerCase()}`);

    const freqMap = store.get().state.cell?.ref?.data.threatFrequency;
    if (freqMap) {
        let min = freqMap[Object.keys(freqMap)[0]], choice=Object.keys(freqMap)[0];
        Object.keys(freqMap).forEach((k) => {
            if(freqMap[k]<min)
            {
                min = freqMap[k];
                choice = k;
            }
        });
        typeKey = choice;
        type = tc(`threats.model.${modelType.toLowerCase()}.${choice}`);
    } else {
        switch (modelType) {

        case 'CIA':
            title = tc('threats.generic.cia');
            type = tc('threats.model.cia.confidentiality');
            break;

        case 'CIADIE':
            title = tc('threats.generic.ciadie');
            type = tc('threats.model.ciadie.distributed');
            break;

        case 'LINDDUN':
            title = tc('threats.generic.linddun');
            type = tc('threats.model.linddun.linkability');
            break;

        case 'PLOT4ai':
            title = tc('threats.generic.plot4ai');
            if (cellType === 'tm.Actor') {
                type = tc('threats.model.plot4ai.accessibility');
            } else {
                type = tc('threats.model.plot4ai.techniqueProcesses');
            }
            break;

        case 'STRIDE':
            title = tc('threats.generic.stride');
            if (cellType === 'tm.Actor' || cellType === 'tm.Process') {
                type = tc('threats.model.stride.spoofing');
            } else {
                type = tc('threats.model.stride.tampering');
            }
            break;

        case 'WEB3':
            title = tc('threats.generic.web3');
            typeKey = web3DefaultTypeKey(cellType);
            type = tc(`threats.model.web3.${typeKey}`);
            break;

        case 'EOP':
            title = tc('threats.generic.eop');
            type = 'cornucopia';
            break;

        default:
            title = tc('threats.generic.default');
            type = tc('threats.model.stride.spoofing');
            break;
        }
    }

    const threat = {
        id: uuidv4(),
        title,
        status: 'Open',
        severity: 'TBD',
        type,
        description: tc('threats.description'),
        mitigation: tc('threats.mitigation'),
        modelType,
        new: true,
        number: number,
        score: ''
    };

    // WEB3 rules engine: pre-fill an experience-based threat from the rules
    // library instead of the generic placeholders.
    if (modelType === 'WEB3') {
        applyWeb3Rule(threat, typeKey);
    }

    return threat;
};

const hasOpenThreats = (data) => !!data && !!data.threats &&
    data.threats.filter(x => isOpen(x.status)).length > 0;

const filter = (diagrams, filters) => {
    return diagrams
        .flatMap(x => x.cells)
        .filter(x => !!x.data && !!x.data.threats)
        .flatMap(x => x.data.threats)
        .filter(x => filterForDiagram(x, filters))
        .filter(x => !!x);
};

const filterForDiagram = (data, filters) => {
    if (!filters.showOutOfScope && data.outOfScope) {
        return [];
    }

    if (!data.threats) {
        return [];
    }

    return data.threats.filter(x => filters.showMitigated || !isResolved(x.status));
};

export default {
    convertToTranslationString,
    filter,
    filterForDiagram,
    getModelByTranslation: models.getByTranslationValue,
    hasOpenThreats
};
