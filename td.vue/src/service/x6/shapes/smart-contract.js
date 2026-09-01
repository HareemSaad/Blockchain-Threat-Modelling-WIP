import { Shape } from '@antv/x6';

import { tc } from '@/i18n/index.js';

import { ports } from '../ports.js';

const name = 'smart-contract';

// smart contract (hexagon, transparent background) - distinct from Process (circle)
// to signal on-chain code. refPoints are auto-scaled to the node's bounding box.
export const SmartContractShape = Shape.Polygon.define({
    constructorName: name,
    width: 130,
    height: 90,
    zIndex: 0,
    label: tc('threatmodel.shapes.smartContract'),
    attrs: {
        body: {
            refPoints: '25,0 75,0 100,50 75,100 25,100 0,50',
            fill: 'transparent',
            fillOpacity: 0,
            stroke: '#333333',
            strokeWidth: 1.5
        }
    },
    ports: { ...ports }
});

SmartContractShape.prototype.type = 'tm.SmartContract';

SmartContractShape.prototype.setName = function (name) {
    this.label = name;
};

SmartContractShape.prototype.updateStyle = function (color, dash, strokeWidth) {
    this.setAttrByPath('body/stroke', color);
    this.setAttrByPath('body/strokeWidth', strokeWidth);
    this.setAttrByPath('body/strokeDasharray', dash);
};

export default {
    name,
    SmartContractShape
};
