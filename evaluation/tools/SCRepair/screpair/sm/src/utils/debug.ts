/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 * 
 */


import debug from 'debug';

debug.formatters.e = fn => fn();

export default debug;