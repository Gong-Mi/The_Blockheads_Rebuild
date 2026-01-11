//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;

varying highp vec4 outTexCoord;
varying highp vec4 outCloud;

void main()
{
    highp vec4 fog = vec4(outCloud.y,outCloud.y, outCloud.y, 1.0);
    highp vec4 tex = texture2D(texture, outTexCoord.xy) * vec4(outCloud.y, outCloud.y, outCloud.y, 1.0) * vec4(outTexCoord.z, outTexCoord.z, outTexCoord.z, 1.0);
    
    highp vec4 texShaded = mix(vec4(0.0,0.0,0.0,1.0), tex, min((outCloud.y + tex.a), 1.0));
    
    //highp vec4 texShaded = tex;
    
    gl_FragColor = mix(texShaded, fog, vec4(outCloud.x, outCloud.x, outCloud.x, outCloud.x));
}
