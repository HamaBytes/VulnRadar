import { motion } from "framer-motion";
import { cn } from "../../utils/utils";


interface ScoreRingProps {
    value: number;

    min?: number;
    max: number;

    size?: number;
    strokeWidth?: number;

    label?: string;

    formatter?: (
        value: number,
        percentage: number
    ) => string;


    colorResolver?: (
        percentage: number
    ) => string;

    className?: string;
}



const defaultColorResolver = (
    percentage:number
)=>{

    if(percentage >= 90)
        return "var(--error)";

    if(percentage >= 70)
        return "var(--primary)";

    if(percentage >= 40)
        return "var(--secondary)";

    return "var(--terminal-green)";
};



export function ScoreRing({
                              value,

                              min = 0,
                              max,

                              size = 120,
                              strokeWidth = 10,

                              label,

                              formatter,

                              colorResolver = defaultColorResolver,

                              className

                          }:ScoreRingProps){


    const percentage =
        Math.min(
            Math.max(
                ((value-min)/(max-min))*100,
                0
            ),
            100
        );



    const radius =
        (size-strokeWidth)/2;



    const circumference =
        2*Math.PI*radius;



    const offset =
        circumference -
        (percentage/100)*circumference;



    const color =
        colorResolver(percentage);



    return (

        <div

            className={cn(
            "relative flex items-center justify-center",
            className
    )}

    style={{
        width:size,
            height:size
    }}

>


    <svg
        width={size}
    height={size}
    className="-rotate-90"
    >


    <circle

        cx={size/2}
    cy={size/2}
    r={radius}

    fill="none"

    stroke="var(--outline)"

    strokeWidth={strokeWidth}

    />



    <motion.circle

    cx={size/2}
    cy={size/2}

    r={radius}

    fill="none"

    stroke={color}

    strokeWidth={strokeWidth}

    strokeLinecap="round"


    strokeDasharray={
        circumference
    }


    initial={{
        strokeDashoffset:circumference
    }}


    animate={{
        strokeDashoffset:offset
    }}


    transition={{
        duration:0.8
    }}

    />


    </svg>



    <div className="absolute flex flex-col items-center">


    <span className="text-xl font-bold">

    {
        formatter
        ? formatter(value,percentage)
        : value
}

    </span>



    {
        label &&
        <span className="text-xs">
            {label}
            </span>
    }


    </div>


    </div>

);
}