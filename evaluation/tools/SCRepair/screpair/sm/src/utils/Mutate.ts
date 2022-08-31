/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 * 
 */


import ora from 'ora';
import { mutateSrc } from '../lib/mutate';
import MutationSequence from '../lib/MutationSequence';

export default function mutate(srcStr: string, mutationSeq: MutationSequence) {
  const spinner = ora('Processing...').start();

  console.log(mutateSrc(srcStr, mutationSeq));

  spinner.succeed('Done!');
}
