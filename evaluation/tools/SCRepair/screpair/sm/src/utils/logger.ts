/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 * 
 */


import winston from 'winston';
import { parse as yesNoParse } from 'yes-no';

const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.cli(),
    winston.format.printf(info => {
      return `${info.timestamp} ${info.level}: ${info.message}`;
    }),
  ),
  level: typeof process.env.DEBUG !== 'undefined' && yesNoParse(process.env.DEBUG) ? 'debug' : 'info',
  transports: [
    new winston.transports.Console({
      stderrLevels: ['debug', 'error', 'info'],
    }),
  ],
});

export default logger;
