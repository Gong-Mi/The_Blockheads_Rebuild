//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;


varying highp vec4 outShades;
varying highp vec2 outShadeCoords;
//varying highp vec4 outColor;

void main()
{
    highp float xLerpTop = mix(outShades.y, outShades.z, outShadeCoords.x);
    highp float xLerpBot = mix(outShades.x, outShades.w, outShadeCoords.x);
    
    highp float yLerpLeft = mix(outShades.x, outShades.y, outShadeCoords.y);
    highp float yLerpRight = mix(outShades.w, outShades.z, outShadeCoords.y);
    
    highp float yLerp = mix(xLerpBot, xLerpTop, outShadeCoords.y);
    highp float xLerp = mix(yLerpLeft, yLerpRight, outShadeCoords.x);
    
    highp float result = xLerp * 0.5 + yLerp * 0.5;
    
    gl_FragColor = vec4(0.0,0.0,0.0,result);// * color;
}
